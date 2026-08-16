-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: Çekirdek şema (11 tablo)
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- FlowLedger Backend v1 — Nihai Çekirdek Şema (16 Ağustos 2026)
-- Kapsam: dijital defter + opsiyonel donanım (otomatik kayıt + uzaktan kontrol).
-- Tarla/hava/sensör YOK. Tablo sayısı artıyor, ürün kapsamı artmıyor.

-- Eski şema tamamen kaldırılıyor (production'da gerçek veri yok, onaylandı).
drop table if exists okumalar cascade;
drop table if exists donemler cascade;
drop table if exists members cascade;
drop table if exists groups cascade;

-- ===== profiles =====
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (length(trim(display_name)) > 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- ===== groups =====
create table groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) > 0),
  join_code text not null unique,
  status text not null default 'active' check (status in ('active','archived')),
  created_at timestamptz not null default now()
);

-- ===== group_memberships =====
create table group_memberships (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references groups(id),
  user_id uuid not null references auth.users(id),
  status text not null default 'active' check (status in ('active','removed')),
  joined_at timestamptz not null default now(),
  unique (group_id, user_id)
);
create index idx_group_memberships_group on group_memberships(group_id);
create index idx_group_memberships_user on group_memberships(user_id);

-- ===== devices =====
create table devices (
  id uuid primary key default gen_random_uuid(),
  group_id uuid references groups(id),
  device_uid text not null unique,
  status text not null default 'unassigned' check (status in ('unassigned','active','inactive')),
  firmware_version text,
  secret_hash text, -- gerçek auth credential'ı asla plaintext saklanmaz; hash bile normal kullanıcıya kapalı (bkz. column grants)
  last_seen_at timestamptz,
  installed_at timestamptz,
  created_at timestamptz not null default now()
);
create index idx_devices_group on devices(group_id);

-- ===== usage_sessions (merkez tablo) =====
create table usage_sessions (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references groups(id),
  user_id uuid not null references auth.users(id),
  device_id uuid references devices(id),
  status text not null default 'active' check (status in ('armed','active','completed','cancelled')),
  source text not null check (source in ('manual','assisted','remote','device_unassigned')),
  meter_start numeric check (meter_start is null or meter_start >= 0),
  meter_end numeric check (meter_end is null or meter_end >= 0),
  energy_used numeric check (energy_used is null or energy_used >= 0),
  started_at timestamptz not null default now(),
  ended_at timestamptz,
  created_at timestamptz not null default now(),
  constraint meter_order check (meter_end is null or meter_start is null or meter_end >= meter_start)
);
create index idx_usage_sessions_group_started on usage_sessions(group_id, started_at);
create index idx_usage_sessions_user on usage_sessions(user_id);
create index idx_usage_sessions_device on usage_sessions(device_id);

-- ===== billing_periods =====
create table billing_periods (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references groups(id),
  bill_date date not null,
  total_amount numeric not null check (total_amount > 0),
  bill_energy numeric check (bill_energy is null or bill_energy >= 0),
  allocation_method text not null check (allocation_method in ('oransal','esit')),
  created_at timestamptz not null default now(),
  unique (group_id, bill_date)
);
create index idx_billing_periods_group_date on billing_periods(group_id, bill_date);

-- ===== allocations (snapshot, immutable) =====
create table allocations (
  id uuid primary key default gen_random_uuid(),
  billing_period_id uuid not null references billing_periods(id),
  user_id uuid not null references auth.users(id),
  usage_energy numeric not null check (usage_energy >= 0),
  amount numeric not null check (amount >= 0),
  created_at timestamptz not null default now(),
  unique (billing_period_id, user_id)
);
create index idx_allocations_billing_period on allocations(billing_period_id);
create index idx_allocations_user on allocations(user_id);

-- ===== device_events (append-only, ham telemetri) =====
create table device_events (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references devices(id),
  group_id uuid not null references groups(id),
  event_type text not null,
  payload jsonb,
  occurred_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);
create index idx_device_events_device_time on device_events(device_id, occurred_at);
create index idx_device_events_group on device_events(group_id);

-- ===== device_commands =====
create table device_commands (
  id uuid primary key default gen_random_uuid(),
  device_id uuid not null references devices(id),
  group_id uuid not null references groups(id),
  requested_by uuid not null references auth.users(id),
  command text not null,
  status text not null default 'requested' check (status in ('requested','sent','acknowledged','completed','failed','cancelled')),
  created_at timestamptz not null default now(),
  executed_at timestamptz,
  failure_reason text
);
create index idx_device_commands_device on device_commands(device_id);
create index idx_device_commands_group on device_commands(group_id);

-- ===== member_entitlements =====
create table member_entitlements (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references groups(id),
  user_id uuid not null references auth.users(id),
  feature text not null check (feature in ('automatic_logging','remote_control')),
  status text not null default 'active' check (status in ('active','revoked')),
  starts_at timestamptz not null default now(),
  expires_at timestamptz,
  created_at timestamptz not null default now(),
  unique (group_id, user_id, feature)
);
create index idx_entitlements_group_user on member_entitlements(group_id, user_id);

-- ===== audit_events (append-only) =====
create table audit_events (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid references auth.users(id),
  group_id uuid references groups(id),
  action text not null,
  target_type text,
  target_id uuid,
  metadata jsonb,
  created_at timestamptz not null default now()
);
create index idx_audit_events_group_time on audit_events(group_id, created_at);
create index idx_audit_events_actor on audit_events(actor_id);
