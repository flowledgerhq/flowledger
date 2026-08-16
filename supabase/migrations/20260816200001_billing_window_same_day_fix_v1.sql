-- FlowLedger Backend v1 — Aynı Gün Fatura Sonrası Kayıt Kaybı Düzeltmesi (16 Ağustos 2026)
--
-- Bulunan hata: create_billing_period()'daki dönem penceresi sınırı,
-- fatura tarihinin (bill_date) GÜN SONUNU kullanıyordu. Bu, bir fatura
-- girildikten SONRA aynı takvim günü içinde tamamlanan bir kullanımın,
-- o pencerenin tarih aralığına düşüp ama o anda henüz var olmadığı için
-- İLK faturaya dahil edilmemesine, sonraki faturanın penceresinin de
-- (window_start aynı gün sonuna sabitlendiği için) onu dışarıda
-- bırakmasına — yani kaydın HİÇBİR faturaya dahil olmadan kaybolmasına
-- yol açıyordu. Test ile doğrulandı ve reprodüklendi.
--
-- Bu, eski (backend v1 öncesi) uygulamada zaten bilinip düzeltilmiş
-- (billCutoffTimestamp() — fatura tarihi gün sonu ile faturanın gerçekten
-- kaydedildiği an arasında hangisi daha erkense onu kullanma) bir sorunun
-- backend v1'e geçişte kaybolmuş halidir. Şimdi aynı mantık backend'e
-- (create_billing_period RPC'sine) taşınıyor.
--
-- Düzeltme: pencere sınırı artık her fatura için
-- LEAST(bill_date gün sonu, o billing_period kaydının gerçekten
-- oluşturulduğu an) olarak hesaplanıyor. Böylece bir fatura girildikten
-- sonra aynı gün eklenen kullanımlar hiçbir zaman o faturaya dahil
-- olmuyor (zaten istenmeyen davranış buydu) VE bir sonraki faturanın
-- penceresi bu gerçek ana göre başlıyor, dolayısıyla kayıt kaybolmuyor —
-- doğru şekilde sonraki (henüz kapanmamış) döneme düşüyor.

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
  v_prev billing_periods;
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

  select * into v_prev from billing_periods
    where group_id = p_group_id and id != v_period.id and bill_date < p_bill_date
    order by bill_date desc limit 1;

  -- Pencere sınırı: bill_date'in gün sonu İLE faturanın gerçekten
  -- kaydedildiği an (created_at) arasında HANGİSİ DAHA ERKENSE onu kullan.
  -- Bu, aynı gün fatura girildikten sonra eklenen kayıtların bu faturaya
  -- sızmasını engeller VE bir sonraki dönemin başlangıcını doğru yere
  -- (faturanın gerçekten kapandığı an) sabitler — kayıt kaybını önler.
  v_window_start := case
    when v_prev.id is null then '-infinity'::timestamptz
    else least(v_prev.bill_date::timestamptz + interval '1 day' - interval '1 microsecond', v_prev.created_at)
  end;
  v_window_end := least(p_bill_date::timestamptz + interval '1 day' - interval '1 microsecond', v_period.created_at);

  select coalesce(sum(energy_used), 0), count(distinct user_id) into v_kayitli_toplam, v_member_count
    from usage_sessions
    where group_id = p_group_id and status = 'completed'
      and coalesce(ended_at, started_at) > v_window_start
      and coalesce(ended_at, started_at) <= v_window_end;

  if p_bill_energy is not null and v_kayitli_toplam > 0 then
    v_fark := p_bill_energy - v_kayitli_toplam;
  end if;

  if v_member_count = 0 then
    insert into audit_events (actor_id, group_id, action, target_type, target_id)
      values (v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id);
    return v_period;
  end if;

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
