-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: Kullanıcı RPC-leri (create_group/join_group/start_manual_usage/complete_usage/create_billing_period)
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- Kullanıcı RPC'leri — frontend artık tablolara doğrudan yazmıyor (RPC-first).

create or replace function generate_join_code()
returns text
language plpgsql
security definer
set search_path = public
as $$
declare
  chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  result text := '';
  i int;
begin
  for i in 1..8 loop
    result := result || substr(chars, floor(random() * length(chars) + 1)::int, 1);
  end loop;
  return result;
end;
$$;
revoke all on function generate_join_code() from public, anon, authenticated;

-- create_group(name): yeni grup + çağıranı active üyeliğe ekler.
create or replace function create_group(p_name text)
returns table(group_id uuid, name text, join_code text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_group groups;
  v_code text;
  v_attempts int := 0;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from profiles where id = v_uid) then
    raise exception 'PROFILE_MISSING';
  end if;
  if p_name is null or length(trim(p_name)) = 0 then raise exception 'INVALID_GROUP_NAME'; end if;

  loop
    v_attempts := v_attempts + 1;
    v_code := generate_join_code();
    begin
      insert into groups (name, join_code) values (trim(p_name), v_code) returning * into v_group;
      exit;
    exception when unique_violation then
      if v_attempts >= 10 then raise exception 'JOIN_CODE_GENERATION_FAILED'; end if;
    end;
  end loop;

  insert into group_memberships (group_id, user_id, status) values (v_group.id, v_uid, 'active');
  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, v_group.id, 'group_created', 'group', v_group.id);

  return query select v_group.id, v_group.name, v_group.join_code;
end;
$$;
revoke all on function create_group(text) from public, anon;
grant execute on function create_group(text) to authenticated;

-- join_group(code): var olan gruba çağıranı active üyeliğe ekler (çoklu grup destekli).
create or replace function join_group(p_code text)
returns table(group_id uuid, name text)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_group groups;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from profiles where id = v_uid) then
    raise exception 'PROFILE_MISSING';
  end if;

  select * into v_group from groups where join_code = upper(trim(p_code)) and status = 'active';
  if v_group is null then raise exception 'INVALID_JOIN_CODE'; end if;

  if exists (select 1 from group_memberships gm where gm.group_id = v_group.id and gm.user_id = v_uid and gm.status = 'active') then
    raise exception 'ALREADY_MEMBER';
  end if;

  insert into group_memberships (group_id, user_id, status) values (v_group.id, v_uid, 'active');
  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, v_group.id, 'member_joined', 'group', v_group.id);

  return query select v_group.id, v_group.name;
end;
$$;
revoke all on function join_group(text) from public, anon;
grant execute on function join_group(text) to authenticated;

-- start_manual_usage(group_id, meter_start): manuel kullanım oturumu açar.
create or replace function start_manual_usage(p_group_id uuid, p_meter_start numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_row usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from group_memberships where group_id = p_group_id and user_id = v_uid and status = 'active') then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;
  if p_meter_start is null or p_meter_start < 0 then raise exception 'INVALID_METER_START'; end if;

  insert into usage_sessions (group_id, user_id, status, source, meter_start, started_at)
    values (p_group_id, v_uid, 'active', 'manual', p_meter_start, now())
    returning * into v_row;

  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, p_group_id, 'usage_started', 'usage_session', v_row.id);

  return v_row;
end;
$$;
revoke all on function start_manual_usage(uuid, numeric) from public, anon;
grant execute on function start_manual_usage(uuid, numeric) to authenticated;

-- complete_usage(session_id, meter_end): açık oturumu kapatır, energy_used server-side türetilir.
create or replace function complete_usage(p_session_id uuid, p_meter_end numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_session usage_sessions;
  v_row usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  select * into v_session from usage_sessions where id = p_session_id;
  if v_session is null then raise exception 'SESSION_NOT_FOUND'; end if;
  if not exists (select 1 from group_memberships where group_id = v_session.group_id and user_id = v_uid and status = 'active') then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;
  if v_session.status not in ('armed','active') then raise exception 'SESSION_NOT_OPEN'; end if;
  if p_meter_end is null or (v_session.meter_start is not null and p_meter_end < v_session.meter_start) then
    raise exception 'INVALID_METER_END';
  end if;

  update usage_sessions
  set meter_end = p_meter_end,
      energy_used = case when meter_start is not null then p_meter_end - meter_start else null end,
      ended_at = now(),
      status = 'completed'
  where id = p_session_id
  returning * into v_row;

  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, v_row.group_id, 'usage_completed', 'usage_session', v_row.id);

  return v_row;
end;
$$;
revoke all on function complete_usage(uuid, numeric) from public, anon;
grant execute on function complete_usage(uuid, numeric) to authenticated;

-- create_billing_period(...): fatura oluşturur VE paylaşım sonucunu snapshot olarak allocations'a yazar.
-- Dönem penceresi: bu gruptaki en son billing_period'dan (varsa) bu bill_date'e kadarki completed usage_sessions.
create or replace function create_billing_period(
  p_group_id uuid, p_bill_date date, p_total_amount numeric,
  p_bill_energy numeric, p_allocation_method text
)
returns billing_periods
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_period billing_periods;
  v_prev_date date;
  v_window_start timestamptz;
  v_window_end timestamptz;
  v_total_energy numeric;
  v_member_count int;
  r record;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from group_memberships where group_id = p_group_id and user_id = v_uid and status = 'active') then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;
  if p_total_amount is null or p_total_amount <= 0 then raise exception 'INVALID_TOTAL_AMOUNT'; end if;
  if p_allocation_method not in ('oransal','esit') then raise exception 'INVALID_ALLOCATION_METHOD'; end if;

  insert into billing_periods (group_id, bill_date, total_amount, bill_energy, allocation_method)
    values (p_group_id, p_bill_date, p_total_amount, p_bill_energy, p_allocation_method)
    returning * into v_period;

  select max(bill_date) into v_prev_date from billing_periods
    where group_id = p_group_id and id != v_period.id and bill_date < p_bill_date;
  v_window_start := case when v_prev_date is null then '-infinity'::timestamptz else (v_prev_date::timestamptz + interval '1 day' - interval '1 microsecond') end;
  v_window_end := (p_bill_date::timestamptz + interval '1 day' - interval '1 microsecond');

  select coalesce(sum(energy_used), 0) into v_total_energy
    from usage_sessions
    where group_id = p_group_id and status = 'completed'
      and coalesce(ended_at, started_at) > v_window_start
      and coalesce(ended_at, started_at) <= v_window_end;

  if p_allocation_method = 'oransal' and v_total_energy > 0 then
    for r in (
      select user_id, sum(energy_used) as energy
      from usage_sessions
      where group_id = p_group_id and status = 'completed'
        and coalesce(ended_at, started_at) > v_window_start
        and coalesce(ended_at, started_at) <= v_window_end
      group by user_id
    ) loop
      insert into allocations (billing_period_id, user_id, usage_energy, amount)
        values (v_period.id, r.user_id, r.energy, round(p_total_amount * r.energy / v_total_energy, 2));
    end loop;
  else
    -- esit dağıtım, veya oransalda toplam tüketim 0 ise: dönemde kullanımı olan üyeler arasında eşit böl
    select count(distinct user_id) into v_member_count
      from usage_sessions
      where group_id = p_group_id and status = 'completed'
        and coalesce(ended_at, started_at) > v_window_start
        and coalesce(ended_at, started_at) <= v_window_end;
    if v_member_count > 0 then
      for r in (
        select user_id, coalesce(sum(energy_used), 0) as energy
        from usage_sessions
        where group_id = p_group_id and status = 'completed'
          and coalesce(ended_at, started_at) > v_window_start
          and coalesce(ended_at, started_at) <= v_window_end
        group by user_id
      ) loop
        insert into allocations (billing_period_id, user_id, usage_energy, amount)
          values (v_period.id, r.user_id, r.energy, round(p_total_amount / v_member_count, 2));
      end loop;
    end if;
  end if;

  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id);

  return v_period;
end;
$$;
revoke all on function create_billing_period(uuid, date, numeric, numeric, text) from public, anon;
grant execute on function create_billing_period(uuid, date, numeric, numeric, text) to authenticated;
