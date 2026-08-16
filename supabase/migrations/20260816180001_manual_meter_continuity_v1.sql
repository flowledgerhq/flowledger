-- FlowLedger Backend v1 — manual_meter_continuity_v1 (16 Ağustos 2026)
-- Production'a Kazım tarafından doğrudan uygulanmıştı; bu dosya SQL
-- sorgularıyla doğrulanan gerçek production tanımlarının kaydıdır
-- (kör migration DEĞİL — önce introspect edildi, sonra buraya yazıldı).
--
-- Amaç: manuel sayaç zincirinde önceki tamamlanmış kullanımın kapanışını
-- yeni açılışın "beklenen" değeri olarak izlemek — dönem sonunu beklemeden
-- hangi iki kullanım arasında sayaç farkı oluştuğunu görünür kılmak.
--
-- NOT idempotent (tek seferlik, zaten uygulanmış production durumunun kaydı).

alter table usage_sessions add column previous_session_id uuid references usage_sessions(id);
alter table usage_sessions add column expected_meter_start numeric;
alter table usage_sessions add column meter_gap numeric generated always as (
  case when meter_start is null or expected_meter_start is null then null
  else meter_start - expected_meter_start end
) stored;

-- Son tamamlanmış kullanımın kapanışını (varsa) döndürür — "Okuma Ekle"
-- ekranı açılırken frontend'in beklenen açılış değerini göstermesi için.
create or replace function get_manual_usage_start_context(p_group_id uuid)
returns table(expected_meter_start numeric, previous_session_id uuid, previous_user_id uuid, previous_ended_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (
    select 1 from public.group_memberships
    where group_id = p_group_id and user_id = v_uid and status = 'active'
  ) then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;

  return query
  select s.meter_end, s.id, s.user_id, s.ended_at
  from public.usage_sessions s
  where s.group_id = p_group_id
    and s.status = 'completed'
    and s.meter_end is not null
  order by s.ended_at desc nulls last, s.started_at desc, s.id desc
  limit 1;
end;
$$;
revoke all on function get_manual_usage_start_context(uuid) from public, anon;
grant execute on function get_manual_usage_start_context(uuid) to authenticated;

-- start_manual_usage: aynı imza korunuyor (p_group_id, p_meter_start).
-- Artık previous_session_id/expected_meter_start'ı kendi bulup dolduruyor,
-- ve gözlenen açılış son kapanıştan küçükse reddediyor. Fark varsa
-- (meter_gap != 0) ek olarak meter_discrepancy_detected audit event'i
-- oluşturuyor (kullanım geçmişinden farkın hangi iki kayıt arasında
-- oluştuğu izlenebilir hale geliyor).
create or replace function start_manual_usage(p_group_id uuid, p_meter_start numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_row public.usage_sessions;
  v_prev public.usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (
    select 1 from public.group_memberships
    where group_id = p_group_id and user_id = v_uid and status = 'active'
  ) then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;
  if p_meter_start is null or p_meter_start < 0 then raise exception 'INVALID_METER_START'; end if;

  select * into v_prev
  from public.usage_sessions
  where group_id = p_group_id
    and status = 'completed'
    and meter_end is not null
  order by ended_at desc nulls last, started_at desc, id desc
  limit 1;

  if v_prev.id is not null and p_meter_start < v_prev.meter_end then
    raise exception 'METER_START_BELOW_PREVIOUS_END'
      using detail = format('previous_end=%s observed_start=%s', v_prev.meter_end, p_meter_start),
            hint = 'Yeni manuel açılış değeri son tamamlanmış kapanış değerinden küçük olamaz.';
  end if;

  insert into public.usage_sessions (
    group_id, user_id, status, source, meter_start, started_at,
    previous_session_id, expected_meter_start
  ) values (
    p_group_id, v_uid, 'active', 'manual', p_meter_start, now(),
    v_prev.id, v_prev.meter_end
  )
  returning * into v_row;

  insert into public.audit_events (
    actor_id, group_id, action, target_type, target_id, metadata
  ) values (
    v_uid, p_group_id, 'usage_started', 'usage_session', v_row.id,
    jsonb_strip_nulls(jsonb_build_object(
      'previous_session_id', v_row.previous_session_id,
      'expected_meter_start', v_row.expected_meter_start,
      'observed_meter_start', v_row.meter_start,
      'meter_gap', v_row.meter_gap
    ))
  );

  if v_row.meter_gap is not null and v_row.meter_gap <> 0 then
    insert into public.audit_events (
      actor_id, group_id, action, target_type, target_id, metadata
    ) values (
      v_uid, p_group_id, 'meter_discrepancy_detected', 'usage_session', v_row.id,
      jsonb_build_object(
        'previous_session_id', v_row.previous_session_id,
        'expected_meter_start', v_row.expected_meter_start,
        'observed_meter_start', v_row.meter_start,
        'meter_gap', v_row.meter_gap
      )
    );
  end if;

  return v_row;
end;
$$;
revoke all on function start_manual_usage(uuid, numeric) from public, anon;
grant execute on function start_manual_usage(uuid, numeric) to authenticated;
