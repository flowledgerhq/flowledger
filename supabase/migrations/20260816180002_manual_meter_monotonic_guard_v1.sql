-- FlowLedger Backend v1 — manual_meter_monotonic_guard_v1 (16 Ağustos 2026)
-- Production'a Kazım tarafından doğrudan uygulanmıştı; introspect edilip
-- kaydedildi. RPC seviyesindeki METER_START_BELOW_PREVIOUS_END kontrolüne
-- ek, DB seviyesinde bağımsız bir güvenlik katmanı — start_manual_usage
-- dışında bir yoldan (ör. ileride başka bir RPC/servis) manuel bir
-- usage_session eklenirse de aynı kural zorunlu kalır.
--
-- NOT idempotent (tek seferlik, zaten uygulanmış production durumunun kaydı).

create or replace function enforce_manual_meter_monotonicity()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_previous_end numeric;
begin
  if new.source <> 'manual' then
    return new;
  end if;

  select s.meter_end
    into v_previous_end
  from public.usage_sessions s
  where s.group_id = new.group_id
    and s.status = 'completed'
    and s.meter_end is not null
  order by s.ended_at desc nulls last, s.started_at desc, s.id desc
  limit 1;

  if v_previous_end is not null
     and new.meter_start is not null
     and new.meter_start < v_previous_end then
    raise exception 'METER_START_BELOW_PREVIOUS_END'
      using detail = format('previous_end=%s observed_start=%s', v_previous_end, new.meter_start),
            hint = 'Yeni manuel açılış değeri son tamamlanmış kapanış değerinden küçük olamaz.';
  end if;

  return new;
end;
$$;
revoke all on function enforce_manual_meter_monotonicity() from public, anon, authenticated;

drop trigger if exists trg_enforce_manual_meter_monotonicity on usage_sessions;
create trigger trg_enforce_manual_meter_monotonicity
  before insert on usage_sessions
  for each row execute function enforce_manual_meter_monotonicity();
