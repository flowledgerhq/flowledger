-- FlowLedger — Backend Hardening v1 (16 Ağustos 2026)
-- Bu dosya, production Supabase veritabanında bu tarihte doğrulanmış/
-- uygulanmış hardening değişikliklerinin kalıcı kaydıdır. GitHub'daki bu
-- klasör (supabase/migrations/), kaynak kod geçmişi ile production DB
-- durumunun senkron kalması için bu commit'ten itibaren başlatıldı.
--
-- Bu dosya idempotent'tir (tekrar çalıştırılabilir). Gerçek çalıştırma
-- VDS'de /opt/apps/flowledger/migrate_backend_hardening_v1.js üzerinden
-- yapılır (proje alışkanlığı: DB migration'ları VDS'den Node.js + pg ile
-- Session Pooler üzerinden uygulanır); bu .sql dosyası aynı içeriğin
-- repo'daki okunabilir/versiyonlanmış kaydıdır.
--
-- Test: 19/19 senaryo geçti (transaction+rollback ile izole,
-- /opt/apps/flowledger/test_hardening.js).
--
-- Bilinçli olarak kalan Supabase Advisor uyarısı:
-- authenticated_security_definer_function_executable (create_group,
-- join_group) — bu iki RPC SECURITY DEFINER olmak zorunda çünkü
-- members.group_id yalnızca bunlar üzerinden değiştirilebiliyor
-- (trg_protect_members_group_id ile korunuyor). Düzeltilmemeli.

-- ===== 1) search_path sabitlemesi =====
alter function public.complete_usage(uuid, numeric) set search_path = public;
alter function public.protect_okuma_immutability() set search_path = public;
-- create_group/join_group/generate_join_code/protect_members_group_id zaten
-- CREATE OR REPLACE FUNCTION ... SET search_path = public ile tanımlı.

-- ===== 2) Internal fonksiyonlardan EXECUTE yetkisi kaldırma =====
revoke all on function public.generate_join_code() from public, anon, authenticated;
revoke all on function public.protect_members_group_id() from public, anon, authenticated;
revoke all on function public.protect_okuma_immutability() from public, anon, authenticated;

-- ===== 3) Public API RPC'lerinin yetkileri =====
revoke all on function public.create_group(text) from public, anon;
grant execute on function public.create_group(text) to authenticated;
revoke all on function public.join_group(text) from public, anon;
grant execute on function public.join_group(text) to authenticated;
revoke all on function public.complete_usage(uuid, numeric) from public, anon;
grant execute on function public.complete_usage(uuid, numeric) to authenticated;

-- ===== 4) Eksik index =====
create index if not exists idx_okumalar_user_id on public.okumalar(user_id);

-- ===== 5) RLS: auth.uid() -> (select auth.uid()) planner hardening =====
-- Yetkilendirme mantığı DEĞİŞMEDİ, yalnızca planner init-plan optimizasyonu.

drop policy if exists members_select_own on public.members;
create policy members_select_own on public.members
  for select to public
  using ((select auth.uid()) = id);

drop policy if exists members_insert_own on public.members;
create policy members_insert_own on public.members
  for insert to public
  with check ((select auth.uid()) = id);

drop policy if exists members_update_own on public.members;
create policy members_update_own on public.members
  for update to public
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

drop policy if exists okuma_select_own_group on public.okumalar;
create policy okuma_select_own_group on public.okumalar
  for select to public
  using (exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = okumalar.group_id));

drop policy if exists okuma_insert_own_identity on public.okumalar;
create policy okuma_insert_own_identity on public.okumalar
  for insert to public
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = okumalar.group_id)
  );

drop policy if exists complete_open_reading_own_group on public.okumalar;
create policy complete_open_reading_own_group on public.okumalar
  for update to public
  using (
    kapatma_kw is null
    and exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = okumalar.group_id)
  )
  with check (kapatma_kw is not null);

drop policy if exists donem_select_own_group on public.donemler;
create policy donem_select_own_group on public.donemler
  for select to public
  using (exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = donemler.group_id));

drop policy if exists donem_insert_own_group on public.donemler;
create policy donem_insert_own_group on public.donemler
  for insert to public
  with check (exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = donemler.group_id));

drop policy if exists groups_select_own on public.groups;
create policy groups_select_own on public.groups
  for select to authenticated
  using (exists (select 1 from members m where m.id = (select auth.uid()) and m.group_id = groups.id));
