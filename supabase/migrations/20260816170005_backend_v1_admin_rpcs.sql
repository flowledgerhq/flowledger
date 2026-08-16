-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: Admin/provisioning RPC-leri (yalnızca service_role)
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- Admin/provisioning RPC'leri — yalnızca service_role çağırabilir (authenticated/anon'a
-- hiç EXECUTE verilmiyor). Bugün bunları Kazım kendi service_role key'iyle (Claude/ChatGPT
-- admin aracı aracılığıyla) çağırır; ileride gerçek "FlowLedger operator" auth modeli
-- ayrı kurulduğunda bu RPC'lerin EXECUTE yetkisi o role'e taşınabilir.
--
-- İnsan-dostu girdi: device_uid (örn. "FL-55628") ve grup adı/join_code kabul eder,
-- UUID bilmeyi gerektirmez. İsim çakışması varsa ambiguous hatası döner (tahmin etmez).

create or replace function find_group(p_query text)
returns setof groups
language sql
security definer
set search_path = public
as $$
  select * from groups
  where join_code = upper(trim(p_query)) or name ilike '%' || trim(p_query) || '%';
$$;
revoke all on function find_group(text) from public, anon, authenticated;
grant execute on function find_group(text) to service_role;

create or replace function find_device(p_device_uid text)
returns setof devices
language sql
security definer
set search_path = public
as $$
  select * from devices where device_uid = trim(p_device_uid);
$$;
revoke all on function find_device(text) from public, anon, authenticated;
grant execute on function find_device(text) to service_role;

-- assign_device_to_group: device_uid + (join_code ya da tam grup adı). İsim çakışmasında ambiguous hatası.
create or replace function assign_device_to_group(p_device_uid text, p_group_query text)
returns devices
language plpgsql
security definer
set search_path = public
as $$
declare
  v_device devices;
  v_matches int;
  v_group groups;
  v_row devices;
begin
  select * into v_device from devices where device_uid = trim(p_device_uid);
  if v_device is null then raise exception 'DEVICE_NOT_FOUND'; end if;

  select count(*) into v_matches from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';
  if v_matches = 0 then raise exception 'GROUP_NOT_FOUND'; end if;
  if v_matches > 1 then raise exception 'AMBIGUOUS_GROUP_MATCH: % sonuç bulundu, join_code ile netleştir', v_matches; end if;

  select * into v_group from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';

  update devices set group_id = v_group.id, status = 'active' where device_uid = trim(p_device_uid) returning * into v_row;
  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_group.id, 'device_assigned', 'device', v_row.id, jsonb_build_object('device_uid', v_row.device_uid, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function assign_device_to_group(text, text) from public, anon, authenticated;
grant execute on function assign_device_to_group(text, text) to service_role;

create or replace function unassign_device(p_device_uid text)
returns devices
language plpgsql
security definer
set search_path = public
as $$
declare v_row devices; v_group_id uuid;
begin
  select group_id into v_group_id from devices where device_uid = trim(p_device_uid);
  update devices set group_id = null, status = 'unassigned' where device_uid = trim(p_device_uid) returning * into v_row;
  if v_row is null then raise exception 'DEVICE_NOT_FOUND'; end if;
  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_group_id, 'device_unassigned', 'device', v_row.id, jsonb_build_object('device_uid', v_row.device_uid, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function unassign_device(text) from public, anon, authenticated;
grant execute on function unassign_device(text) to service_role;

create or replace function activate_device(p_device_uid text)
returns devices
language plpgsql
security definer
set search_path = public
as $$
declare v_row devices;
begin
  update devices set status = 'active', installed_at = coalesce(installed_at, now())
    where device_uid = trim(p_device_uid) and group_id is not null
    returning * into v_row;
  if v_row is null then raise exception 'DEVICE_NOT_FOUND_OR_UNASSIGNED'; end if;
  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_row.group_id, 'device_activated', 'device', v_row.id, jsonb_build_object('device_uid', v_row.device_uid, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function activate_device(text) from public, anon, authenticated;
grant execute on function activate_device(text) to service_role;

create or replace function deactivate_device(p_device_uid text)
returns devices
language plpgsql
security definer
set search_path = public
as $$
declare v_row devices;
begin
  update devices set status = 'inactive' where device_uid = trim(p_device_uid) returning * into v_row;
  if v_row is null then raise exception 'DEVICE_NOT_FOUND'; end if;
  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_row.group_id, 'device_deactivated', 'device', v_row.id, jsonb_build_object('device_uid', v_row.device_uid, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function deactivate_device(text) from public, anon, authenticated;
grant execute on function deactivate_device(text) to service_role;

-- grant_entitlement / revoke_entitlement: (join_code veya grup adı) + display_name/email ile kullanıcı bulunur.
create or replace function grant_entitlement(p_group_query text, p_user_email text, p_feature text)
returns member_entitlements
language plpgsql
security definer
set search_path = public
as $$
declare
  v_group groups; v_matches int; v_user_id uuid; v_row member_entitlements;
begin
  if p_feature not in ('automatic_logging','remote_control') then raise exception 'INVALID_FEATURE'; end if;
  select count(*) into v_matches from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';
  if v_matches = 0 then raise exception 'GROUP_NOT_FOUND'; end if;
  if v_matches > 1 then raise exception 'AMBIGUOUS_GROUP_MATCH'; end if;
  select * into v_group from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';

  select id into v_user_id from auth.users where email = trim(p_user_email);
  if v_user_id is null then raise exception 'USER_NOT_FOUND'; end if;
  if not exists (select 1 from group_memberships where group_id = v_group.id and user_id = v_user_id and status = 'active') then
    raise exception 'USER_NOT_GROUP_MEMBER';
  end if;

  insert into member_entitlements (group_id, user_id, feature, status)
    values (v_group.id, v_user_id, p_feature, 'active')
    on conflict (group_id, user_id, feature) do update set status = 'active', starts_at = now(), expires_at = null
    returning * into v_row;

  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_group.id, p_feature || '_enabled', 'member_entitlement', v_row.id, jsonb_build_object('user_email', p_user_email, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function grant_entitlement(text, text, text) from public, anon, authenticated;
grant execute on function grant_entitlement(text, text, text) to service_role;

create or replace function revoke_entitlement(p_group_query text, p_user_email text, p_feature text)
returns member_entitlements
language plpgsql
security definer
set search_path = public
as $$
declare
  v_group groups; v_matches int; v_user_id uuid; v_row member_entitlements;
begin
  select count(*) into v_matches from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';
  if v_matches = 0 then raise exception 'GROUP_NOT_FOUND'; end if;
  if v_matches > 1 then raise exception 'AMBIGUOUS_GROUP_MATCH'; end if;
  select * into v_group from groups where join_code = upper(trim(p_group_query)) or name ilike '%' || trim(p_group_query) || '%';

  select id into v_user_id from auth.users where email = trim(p_user_email);
  if v_user_id is null then raise exception 'USER_NOT_FOUND'; end if;

  update member_entitlements set status = 'revoked', expires_at = now()
    where group_id = v_group.id and user_id = v_user_id and feature = p_feature
    returning * into v_row;
  if v_row is null then raise exception 'ENTITLEMENT_NOT_FOUND'; end if;

  insert into audit_events (actor_id, group_id, action, target_type, target_id, metadata)
    values (null, v_group.id, p_feature || '_disabled', 'member_entitlement', v_row.id, jsonb_build_object('user_email', p_user_email, 'actor', 'admin_tool'));
  return v_row;
end;
$$;
revoke all on function revoke_entitlement(text, text, text) from public, anon, authenticated;
grant execute on function revoke_entitlement(text, text, text) to service_role;

-- test_device_connection: gerçek cihaz/protokol yok — sahte implementasyon YAZILMIYOR, açık placeholder.
create or replace function test_device_connection(p_device_uid text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  raise exception 'NOT_IMPLEMENTED: gerçek cihaz protokolü henüz tanımlanmadı';
end;
$$;
revoke all on function test_device_connection(text) from public, anon, authenticated;
grant execute on function test_device_connection(text) to service_role;
