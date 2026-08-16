-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: usage_sessions state-machine koruması
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- Immutability: completed/terminal kayıtlar keyfi değiştirilemez.
-- billing_periods/allocations/device_events/audit_events zaten authenticated/anon'a
-- UPDATE/DELETE grantı verilmiyor (bkz. 03_rls.sql) — bu append-only garanti için yeterli.
-- usage_sessions ise RPC'ler (postgres/owner olarak) UPDATE yapabildiği için, geçersiz
-- state transition'larını ve terminal-sonrası değişimi burada trigger ile engelliyoruz.

create or replace function protect_usage_session_transitions()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if OLD.status in ('completed','cancelled') then
    raise exception 'usage_session % durumda: değiştirilemez', OLD.status;
  end if;
  if NEW.group_id is distinct from OLD.group_id then raise exception 'group_id değiştirilemez'; end if;
  if NEW.user_id is distinct from OLD.user_id then raise exception 'user_id değiştirilemez'; end if;
  if NEW.source is distinct from OLD.source then raise exception 'source değiştirilemez'; end if;
  if NEW.created_at is distinct from OLD.created_at then raise exception 'created_at değiştirilemez'; end if;
  -- yalnızca izin verilen geçişler: armed->active, armed->completed/cancelled, active->completed/cancelled
  if NEW.status = OLD.status then
    -- aynı statüde alan güncellemesi (örn. meter_start düzeltmesi) şimdilik serbest, RPC zaten kontrollü
    return NEW;
  end if;
  if not (
    (OLD.status = 'armed' and NEW.status in ('active','completed','cancelled'))
    or (OLD.status = 'active' and NEW.status in ('completed','cancelled'))
  ) then
    raise exception 'Geçersiz durum geçişi: % -> %', OLD.status, NEW.status;
  end if;
  return NEW;
end;
$$;
drop trigger if exists trg_protect_usage_session_transitions on usage_sessions;
create trigger trg_protect_usage_session_transitions
  before update on usage_sessions
  for each row execute function protect_usage_session_transitions();
revoke all on function protect_usage_session_transitions() from public, anon, authenticated;
