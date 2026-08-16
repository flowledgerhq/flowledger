-- FlowLedger Backend v1 — Nihai Çekirdek Mimari (16 Ağustos 2026)
-- Bölüm: profiles_select_groupmates + fark uzlaştırma mantığı
-- Bu grup NOT idempotent (tek seferlik temel migration) — CREATE TABLE/
-- POLICY guard'sız. Yeniden çalıştırma gerekiyorsa önce ilgili nesneleri
-- (DROP TABLE/POLICY IF EXISTS) elle temizleyin. VDS'de gerçek çalıştırma
-- /opt/apps/flowledger/backend_v1/ altındaki .sql dosyalarından yapıldı.
-- Test: /opt/apps/flowledger/backend_v1/test_backend_v1.js — 50/50 geçti.

-- Fixup 1: grup üyeleri birbirinin display_name'ini görebilsin (paylaşımlı
-- defterde "kim ne kadar kullandı" göstermek için gerekli).
-- ÖNEMLİ: bu kontrol group_memberships'i SECURITY DEFINER bir fonksiyon
-- üzerinden okumak zorunda — aksi halde group_memberships'in kendi RLS'i
-- (yalnızca kendi üyeliğini görme) policy'nin içindeki cross-user join'i
-- de filtreleyip her zaman boş sonuç döndürür (gerçek bir hata olarak
-- test sırasında yakalandı).
create or replace function user_shares_active_group(p_other_user uuid)
returns boolean
language sql
security definer
set search_path = public
stable
as $$
  select exists (
    select 1 from group_memberships gm1
    join group_memberships gm2 on gm1.group_id = gm2.group_id
    where gm1.user_id = p_other_user and gm2.user_id = auth.uid()
      and gm1.status = 'active' and gm2.status = 'active'
  );
$$;
revoke all on function user_shares_active_group(uuid) from public, anon;
grant execute on function user_shares_active_group(uuid) to authenticated;

create policy profiles_select_groupmates on profiles for select to authenticated
  using (user_shares_active_group(profiles.id));

-- Fixup 2: create_billing_period artık eski uygulamadaki "fark" (kayıtlı
-- toplam ile faturadaki toplam kW arasındaki uzlaştırma) mantığını da
-- içeriyor — bu gerçek, mevcut bir özellikti (sayaç kaybı/unutulan kayıt),
-- ilk yazımda atlanmıştı.
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
  v_kayitli_toplam numeric;
  v_fark numeric := 0;
  v_member_count int;
  v_nihai_toplam numeric;
  r record;
  v_recorded numeric;
  v_fark_payi numeric;
  v_effective numeric;
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

  select coalesce(sum(energy_used), 0), count(distinct user_id) into v_kayitli_toplam, v_member_count
    from usage_sessions
    where group_id = p_group_id and status = 'completed'
      and coalesce(ended_at, started_at) > v_window_start
      and coalesce(ended_at, started_at) <= v_window_end;

  if p_bill_energy is not null and v_kayitli_toplam > 0 then
    v_fark := p_bill_energy - v_kayitli_toplam;
  end if;

  if v_member_count = 0 then
    -- bu pencerede hiç tamamlanmış kullanım yok; snapshot boş kalır
    insert into audit_events (actor_id, group_id, action, target_type, target_id)
      values (v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id);
    return v_period;
  end if;

  -- nihai (fark dahil) toplam, oranların paydası için
  if v_fark != 0 and v_kayitli_toplam > 0 then
    v_nihai_toplam := v_kayitli_toplam + v_fark;
  else
    v_nihai_toplam := v_kayitli_toplam;
  end if;

  for r in (
    select user_id, coalesce(sum(energy_used), 0) as energy
    from usage_sessions
    where group_id = p_group_id and status = 'completed'
      and coalesce(ended_at, started_at) > v_window_start
      and coalesce(ended_at, started_at) <= v_window_end
    group by user_id
  ) loop
    v_recorded := r.energy;
    if v_fark != 0 and v_kayitli_toplam > 0 then
      if p_allocation_method = 'esit' then
        v_fark_payi := v_fark / v_member_count;
      else
        v_fark_payi := case when v_kayitli_toplam > 0 then v_fark * (r.energy / v_kayitli_toplam) else 0 end;
      end if;
    else
      v_fark_payi := 0;
    end if;
    v_effective := v_recorded + v_fark_payi;

    insert into allocations (billing_period_id, user_id, usage_energy, amount)
      values (
        v_period.id, r.user_id, v_recorded,
        round(p_total_amount * (case when v_nihai_toplam > 0 then v_effective / v_nihai_toplam else 1.0 / v_member_count end), 2)
      );
  end loop;

  insert into audit_events (actor_id, group_id, action, target_type, target_id)
    values (v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id);

  return v_period;
end;
$$;
revoke all on function create_billing_period(uuid, date, numeric, numeric, text) from public, anon;
grant execute on function create_billing_period(uuid, date, numeric, numeric, text) to authenticated;
