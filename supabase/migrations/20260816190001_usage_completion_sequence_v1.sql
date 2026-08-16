-- FlowLedger Backend v1 — usage_completion_sequence (16 Ağustos 2026)
-- Production'a Kazım tarafından doğrudan uygulanmıştı; bu dosya SQL
-- sorgularıyla doğrulanan gerçek production tanımlarının kaydıdır
-- (kör migration DEĞİL — önce introspect edildi, sonra buraya yazıldı).
--
-- Amaç: "gruptaki son tamamlanmış kullanım hangisi?" sorusunu timestamp/
-- UUID sıralamasından tamamen bağımsız, deterministik hale getirmek.
-- Tek transaction içinde now() donuk kaldığında (bkz. önceki continuity
-- test dosyasının ilk versiyonundaki gerçek sorun) eski
-- "ORDER BY ended_at DESC, started_at DESC, id DESC" sıralaması UUID
-- fallback'ine düşüp yanlış sonuç verebiliyordu.
--
-- NOT idempotent (tek seferlik, zaten uygulanmış production durumunun
-- kaydı). Production'da backfill sırasında trg_protect_usage_session_
-- transitions geçici olarak DISABLE edilip hemen ENABLE edilmişti —
-- migration bunu adım adım yansıtıyor.

create sequence if not exists public.usage_completion_seq;

alter table public.usage_sessions
  add column if not exists completion_seq bigint;

-- completed <-> completion_seq ilişkisi DB seviyesinde zorunlu
alter table public.usage_sessions
  add constraint usage_sessions_completion_seq_status_check
  check (
    (status = 'completed' and completion_seq is not null)
    or (status <> 'completed' and completion_seq is null)
  );

create unique index idx_usage_sessions_completion_seq
  on public.usage_sessions (completion_seq)
  where completion_seq is not null;

-- Mevcut completed kayıtların backfill'i: kronolojik sıraya göre (ended_at,
-- started_at, created_at, id) numaralandırılıyor. Bu, immutability
-- trigger'ının normalde engellediği bir UPDATE olduğu için trigger
-- kontrollü şekilde geçici olarak devre dışı bırakılıp hemen tekrar
-- etkinleştiriliyor.
alter table public.usage_sessions disable trigger trg_protect_usage_session_transitions;

with ordered as (
  select id, row_number() over (
    order by ended_at nulls last, started_at, created_at, id
  ) as rn
  from public.usage_sessions
  where status = 'completed' and completion_seq is null
)
update public.usage_sessions u
set completion_seq = nextval('public.usage_completion_seq')
from ordered o
where u.id = o.id;
-- not: nextval() her satırda çağrıldığı için sıra otomatik artan olur;
-- kritik olan "ordered" CTE'sinin doğru kronolojik sırada üretilmesidir.

alter table public.usage_sessions enable trigger trg_protect_usage_session_transitions;

-- Otomatik atama: yeni completed INSERT'te veya active/armed -> completed
-- geçişinde completion_seq nextval() ile atanıyor. Normal kullanıcı bu
-- fonksiyonu RPC olarak çağıramaz (yalnızca trigger zincirinden çalışır).
create or replace function assign_usage_completion_seq()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.status = 'completed' then
    if tg_op = 'INSERT' then
      if new.completion_seq is null then new.completion_seq := nextval('public.usage_completion_seq'); end if;
    elsif old.status is distinct from 'completed' and new.completion_seq is null then
      new.completion_seq := nextval('public.usage_completion_seq');
    end if;
  elsif new.completion_seq is not null then
    raise exception 'COMPLETION_SEQ_ONLY_FOR_COMPLETED';
  end if;
  return new;
end;
$$;
revoke all on function assign_usage_completion_seq() from public, anon, authenticated;
grant execute on function assign_usage_completion_seq() to service_role;

drop trigger if exists trg_assign_usage_completion_seq on public.usage_sessions;
create trigger trg_assign_usage_completion_seq
  before insert or update of status on public.usage_sessions
  for each row execute function assign_usage_completion_seq();

-- Continuity RPC'leri artık "son tamamlanan" için completion_seq kullanıyor
-- (timestamp DEĞİL). İmza/davranış sözleşmesi aynı kalıyor.
create or replace function get_manual_usage_start_context(p_group_id uuid)
returns table(expected_meter_start numeric, previous_session_id uuid, previous_user_id uuid, previous_ended_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid();
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from public.group_memberships where group_id=p_group_id and user_id=v_uid and status='active') then raise exception 'NOT_A_GROUP_MEMBER'; end if;
  return query
  select s.meter_end, s.id, s.user_id, s.ended_at
  from public.usage_sessions s
  where s.group_id=p_group_id and s.status='completed' and s.meter_end is not null
  order by s.completion_seq desc limit 1;
end;
$$;
revoke all on function get_manual_usage_start_context(uuid) from public, anon;
grant execute on function get_manual_usage_start_context(uuid) to authenticated;

create or replace function start_manual_usage(p_group_id uuid, p_meter_start numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare v_uid uuid := auth.uid(); v_row public.usage_sessions; v_prev public.usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (select 1 from public.group_memberships where group_id=p_group_id and user_id=v_uid and status='active') then raise exception 'NOT_A_GROUP_MEMBER'; end if;
  if p_meter_start is null or p_meter_start < 0 then raise exception 'INVALID_METER_START'; end if;
  select * into v_prev from public.usage_sessions
   where group_id=p_group_id and status='completed' and meter_end is not null
   order by completion_seq desc limit 1;
  if v_prev.id is not null and p_meter_start < v_prev.meter_end then
    raise exception 'METER_START_BELOW_PREVIOUS_END'
      using detail=format('previous_end=%s observed_start=%s',v_prev.meter_end,p_meter_start), hint='Yeni manuel açılış değeri son tamamlanmış kapanış değerinden küçük olamaz.';
  end if;
  insert into public.usage_sessions(group_id,user_id,status,source,meter_start,started_at,previous_session_id,expected_meter_start)
   values(p_group_id,v_uid,'active','manual',p_meter_start,now(),v_prev.id,v_prev.meter_end) returning * into v_row;
  insert into public.audit_events(actor_id,group_id,action,target_type,target_id,metadata)
   values(v_uid,p_group_id,'usage_started','usage_session',v_row.id,jsonb_strip_nulls(jsonb_build_object('previous_session_id',v_row.previous_session_id,'expected_meter_start',v_row.expected_meter_start,'observed_meter_start',v_row.meter_start,'meter_gap',v_row.meter_gap)));
  if v_row.meter_gap is not null and v_row.meter_gap <> 0 then
    insert into public.audit_events(actor_id,group_id,action,target_type,target_id,metadata)
     values(v_uid,p_group_id,'meter_discrepancy_detected','usage_session',v_row.id,jsonb_build_object('previous_session_id',v_row.previous_session_id,'expected_meter_start',v_row.expected_meter_start,'observed_meter_start',v_row.meter_start,'meter_gap',v_row.meter_gap));
  end if;
  return v_row;
end;
$$;
revoke all on function start_manual_usage(uuid, numeric) from public, anon;
grant execute on function start_manual_usage(uuid, numeric) to authenticated;
