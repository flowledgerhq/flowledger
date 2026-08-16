-- FlowLedger Backend v1 — Dönem Sınırının Öğlen (12:00) Baz Alınması (16 Ağustos 2026)
--
-- Önceki sürüm (11_billing_proration.sql) dönem sınırını "gün sonu"
-- (23:59:59.999999) olarak varsayıyordu. Ama gerçek sayaç okumaları
-- gece yapılmıyor — elektrikçiler/okuyucular mesai saatlerinde geliyor.
-- Kazım'ın gözlemiyle: bu varsayımı gün ortasına (öğlen 12:00) çekmek,
-- gerçek okuma anına istatistiksel olarak daha yakın bir tahmin —
-- kesinlik artmıyor (hâlâ bir tahmin, saat bilgisi faturada yok), ama
-- "en kötü durumda ne kadar yanılabiliriz" simetrik olarak küçülüyor.
--
-- NOT idempotent değil (CREATE OR REPLACE FUNCTION olduğu için tekrar
-- çalıştırılabilir, ama önceki migration'ların üzerine yazıyor).

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

  -- Dönem sınırı: bill_date'in ÖĞLENİ (12:00, Türkiye saati) İLE faturanın
  -- gerçekten kaydedildiği an (created_at) arasında HANGİSİ DAHA ERKENSE
  -- onu kullan. Öğlen, sayaç okumalarının gerçekte yapıldığı mesai
  -- saatlerine gece yarısından daha yakın bir tahmin — kesinlik iddiası
  -- yok, yalnızca daha makul bir varsayım. "at time zone Europe/Istanbul"
  -- ile tarih açıkça Türkiye saatine göre yorumlanıyor (DB oturumu UTC).
  v_window_start := case
    when v_prev.id is null then '-infinity'::timestamptz
    else least((v_prev.bill_date::timestamp at time zone 'Europe/Istanbul') + interval '12 hours', v_prev.created_at)
  end;
  v_window_end := least((p_bill_date::timestamp at time zone 'Europe/Istanbul') + interval '12 hours', v_period.created_at);

  -- Süreye orantılı bölme: pencereyle KISMEN kesişen kullanımlar (açması
  -- önceki tarafta, kapatması sonraki tarafta) tam süre oranına göre
  -- bölünüyor. Pencerenin tamamen içinde kalan kullanımlar oran=1,
  -- pencereyle hiç kesişmeyenler sorguya hiç girmiyor — davranış eskisiyle
  -- birebir aynı kalıyor, yalnızca sınırı aşan durumlar artık düzgün
  -- bölünüyor.
  with prorated as (
    select
      user_id,
      case
        when ended_at = started_at then
          case when started_at > v_window_start and started_at <= v_window_end then energy_used else 0 end
        else
          energy_used
          * greatest(0, extract(epoch from (least(ended_at, v_window_end) - greatest(started_at, v_window_start))))
          / extract(epoch from (ended_at - started_at))
      end as prorated_energy
    from usage_sessions
    where group_id = p_group_id and status = 'completed'
      and started_at <= v_window_end and ended_at > v_window_start
  )
  select coalesce(sum(prorated_energy), 0), count(distinct user_id) into v_kayitli_toplam, v_member_count from prorated;

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
    with prorated as (
      select
        user_id,
        case
          when ended_at = started_at then
            case when started_at > v_window_start and started_at <= v_window_end then energy_used else 0 end
          else
            energy_used
            * greatest(0, extract(epoch from (least(ended_at, v_window_end) - greatest(started_at, v_window_start))))
            / extract(epoch from (ended_at - started_at))
        end as prorated_energy
      from usage_sessions
      where group_id = p_group_id and status = 'completed'
        and started_at <= v_window_end and ended_at > v_window_start
    )
    select user_id, coalesce(sum(prorated_energy), 0) as energy from prorated group by user_id
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
