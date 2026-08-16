-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: RLS + grant temizliği (tüm 11 tablo)
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- RLS: her yerde açık, yazma çoğunlukla yalnızca RPC üzerinden (SECURITY DEFINER, table owner olarak RLS'i bypass eder).

alter table profiles enable row level security;
alter table groups enable row level security;
alter table group_memberships enable row level security;
alter table devices enable row level security;
alter table usage_sessions enable row level security;
alter table billing_periods enable row level security;
alter table allocations enable row level security;
alter table device_events enable row level security;
alter table device_commands enable row level security;
alter table member_entitlements enable row level security;
alter table audit_events enable row level security;

-- ===== profiles =====
create policy profiles_select_own on profiles for select to public using ((select auth.uid()) = id);
create policy profiles_insert_own on profiles for insert to public with check ((select auth.uid()) = id);
create policy profiles_update_own on profiles for update to public using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

-- ===== groups =====
-- yalnızca üyesi olunan grup görülebilir; INSERT/UPDATE/DELETE yok (yalnızca RPC/owner)
create policy groups_select_member on groups for select to authenticated
  using (exists (select 1 from group_memberships gm where gm.group_id = groups.id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== group_memberships =====
-- kullanıcı yalnızca kendi üyeliklerini görür; INSERT/UPDATE yalnızca RPC üzerinden
create policy memberships_select_own on group_memberships for select to authenticated
  using (user_id = (select auth.uid()));

-- ===== usage_sessions =====
-- SELECT: kendi grubu. INSERT/UPDATE yok (yalnızca start_manual_usage/complete_usage RPC).
create policy usage_select_own_group on usage_sessions for select to authenticated
  using (exists (select 1 from group_memberships gm where gm.group_id = usage_sessions.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== billing_periods =====
create policy billing_select_own_group on billing_periods for select to authenticated
  using (exists (select 1 from group_memberships gm where gm.group_id = billing_periods.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== allocations =====
create policy allocations_select_own_group on allocations for select to authenticated
  using (exists (
    select 1 from billing_periods bp
    join group_memberships gm on gm.group_id = bp.group_id
    where bp.id = allocations.billing_period_id and gm.user_id = (select auth.uid()) and gm.status = 'active'
  ));

-- ===== devices =====
-- grup üyeleri cihaz metadata'sını görebilir (secret_hash hariç, kolon bazlı grant ile).
create policy devices_select_own_group on devices for select to authenticated
  using (group_id is not null and exists (select 1 from group_memberships gm where gm.group_id = devices.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== device_events =====
create policy device_events_select_own_group on device_events for select to authenticated
  using (exists (select 1 from group_memberships gm where gm.group_id = device_events.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== device_commands =====
create policy device_commands_select_own_group on device_commands for select to authenticated
  using (exists (select 1 from group_memberships gm where gm.group_id = device_commands.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== member_entitlements =====
-- kullanıcı yalnızca kendi entitlement'larını okuyabilir; INSERT/UPDATE/DELETE yok (yalnızca admin RPC).
create policy entitlements_select_own on member_entitlements for select to authenticated
  using (user_id = (select auth.uid()));

-- ===== audit_events =====
-- kullanıcı kendi grubunun audit kayıtlarını okuyabilir; INSERT/UPDATE/DELETE yok (yalnızca RPC ile append).
create policy audit_select_own_group on audit_events for select to authenticated
  using (group_id is not null and exists (select 1 from group_memberships gm where gm.group_id = audit_events.group_id and gm.user_id = (select auth.uid()) and gm.status = 'active'));

-- ===== Grant temizliği =====
-- Supabase yeni tablolara authenticated/anon için varsayılan geniş grant veriyor (ALTER DEFAULT PRIVILEGES).
-- RLS SELECT policy'leri olsa da INSERT/UPDATE/DELETE grantlarını açıkça kısıtlıyoruz;
-- yazma yalnızca SECURITY DEFINER RPC'ler üzerinden (postgres/owner olarak RLS'i bypass ederler).
revoke insert, update, delete on groups from authenticated, anon;
revoke insert, update, delete on group_memberships from authenticated, anon;
revoke insert, update, delete on usage_sessions from authenticated, anon;
revoke insert, update, delete on billing_periods from authenticated, anon;
revoke insert, update, delete on allocations from authenticated, anon;
revoke insert, update, delete on devices from authenticated, anon;
revoke insert, update, delete on device_events from authenticated, anon;
revoke insert, update, delete on device_commands from authenticated, anon;
revoke insert, update, delete on member_entitlements from authenticated, anon;
revoke insert, update, delete on audit_events from authenticated, anon;
revoke all on groups, group_memberships, usage_sessions, billing_periods, allocations,
  devices, device_events, device_commands, member_entitlements, audit_events from anon;

-- devices.secret_hash: grup üyeleri bile göremesin (kolon bazlı yetki)
revoke select on devices from authenticated;
grant select (id, group_id, device_uid, status, firmware_version, last_seen_at, installed_at, created_at) on devices to authenticated;
