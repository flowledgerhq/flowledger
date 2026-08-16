-- FlowLedger Backend v1 — Billing cutoff + duration-overlap proration policy (17 Ağustos 2026)
-- Production introspection sonucundan senkronlandı.
-- Source of truth: bill_date; cutoff: 12:00 Europe/Istanbul.
-- Completed cross-cutoff sessions duration overlap ile prorate edilir.
-- Cutoff öncesi başlayan açık kullanım billing'i kontrollü olarak engeller.

alter table public.billing_periods add column if not exists cutoff_at timestamptz;
update public.billing_periods set cutoff_at = (bill_date::timestamp + interval '12 hours') at time zone 'Europe/Istanbul' where cutoff_at is null;
alter table public.billing_periods alter column cutoff_at set not null;
create index if not exists idx_billing_periods_group_cutoff on public.billing_periods(group_id, cutoff_at);

CREATE OR REPLACE FUNCTION public.create_billing_period(p_group_id uuid, p_bill_date date, p_total_amount numeric, p_bill_energy numeric, p_allocation_method text)
 RETURNS billing_periods
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
declare
  v_uid uuid := auth.uid();
  v_period public.billing_periods;
  v_prev public.billing_periods;
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

  if not exists (
    select 1 from public.group_memberships
    where group_id = p_group_id and user_id = v_uid and status = 'active'
  ) then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;

  if p_bill_date is null then raise exception 'INVALID_BILL_DATE'; end if;
  if p_bill_date > (now() at time zone 'Europe/Istanbul')::date then
    raise exception 'FUTURE_BILL_DATE';
  end if;
  if p_total_amount is null or p_total_amount <= 0 then raise exception 'INVALID_TOTAL_AMOUNT'; end if;
  if p_bill_energy is not null and p_bill_energy < 0 then raise exception 'INVALID_BILL_ENERGY'; end if;
  if p_allocation_method not in ('oransal','esit') then raise exception 'INVALID_ALLOCATION_METHOD'; end if;

  v_window_end := (p_bill_date::timestamp + interval '12 hours') at time zone 'Europe/Istanbul';

  select * into v_prev
  from public.billing_periods
  where group_id = p_group_id
    and cutoff_at < v_window_end
  order by cutoff_at desc
  limit 1;

  v_window_start := case
    when v_prev.id is null then '-infinity'::timestamptz
    else v_prev.cutoff_at
  end;

  -- If a usage started on/before this billing cutoff and is still open,
  -- its total energy is unknowable, so the period cannot be finalized yet.
  if exists (
    select 1
    from public.usage_sessions s
    where s.group_id = p_group_id
      and s.status in ('active','armed')
      and s.started_at <= v_window_end
  ) then
    raise exception 'OPEN_USAGE_CROSSES_BILLING_CUTOFF';
  end if;

  insert into public.billing_periods (
    group_id, bill_date, cutoff_at, total_amount, bill_energy, allocation_method
  ) values (
    p_group_id, p_bill_date, v_window_end, p_total_amount, p_bill_energy, p_allocation_method
  )
  returning * into v_period;

  -- Prorate each completed usage by the fraction of its duration that overlaps
  -- the billing window (previous_cutoff, current_cutoff].
  with prorated as (
    select
      s.user_id,
      case
        when s.ended_at = s.started_at then
          case
            when s.started_at > v_window_start and s.started_at <= v_window_end
              then s.energy_used
            else 0
          end
        else
          s.energy_used
          * greatest(
              0,
              extract(epoch from (
                least(s.ended_at, v_window_end)
                - greatest(s.started_at, v_window_start)
              ))
            )
          / extract(epoch from (s.ended_at - s.started_at))
      end as prorated_energy
    from public.usage_sessions s
    where s.group_id = p_group_id
      and s.status = 'completed'
      and s.energy_used is not null
      and s.started_at <= v_window_end
      and s.ended_at > v_window_start
  )
  select coalesce(sum(prorated_energy), 0), count(distinct user_id)
    into v_kayitli_toplam, v_member_count
  from prorated
  where prorated_energy > 0;

  -- Only after proration do we calculate any invoice-vs-recorded discrepancy.
  if p_bill_energy is not null and v_kayitli_toplam > 0 then
    v_fark := p_bill_energy - v_kayitli_toplam;
  end if;

  if v_member_count = 0 then
    insert into public.audit_events (
      actor_id, group_id, action, target_type, target_id, metadata
    ) values (
      v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id,
      jsonb_build_object(
        'cutoff_at', v_period.cutoff_at,
        'previous_cutoff_at', case when v_prev.id is null then null else v_prev.cutoff_at end,
        'recorded_period_energy', 0
      )
    );
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
        s.user_id,
        case
          when s.ended_at = s.started_at then
            case
              when s.started_at > v_window_start and s.started_at <= v_window_end
                then s.energy_used
              else 0
            end
          else
            s.energy_used
            * greatest(
                0,
                extract(epoch from (
                  least(s.ended_at, v_window_end)
                  - greatest(s.started_at, v_window_start)
                ))
              )
            / extract(epoch from (s.ended_at - s.started_at))
        end as prorated_energy
      from public.usage_sessions s
      where s.group_id = p_group_id
        and s.status = 'completed'
        and s.energy_used is not null
        and s.started_at <= v_window_end
        and s.ended_at > v_window_start
    )
    select user_id, sum(prorated_energy) as energy
    from prorated
    where prorated_energy > 0
    group by user_id
  ) loop
    v_recorded := r.energy;

    if v_fark != 0 and v_kayitli_toplam > 0 then
      if p_allocation_method = 'esit' then
        v_fark_payi := v_fark / v_member_count;
      else
        v_fark_payi := v_fark * (r.energy / v_kayitli_toplam);
      end if;
    else
      v_fark_payi := 0;
    end if;

    v_effective := v_recorded + v_fark_payi;

    insert into public.allocations (
      billing_period_id, user_id, usage_energy, amount
    ) values (
      v_period.id,
      r.user_id,
      v_recorded,
      round(
        p_total_amount * (
          case
            when v_nihai_toplam > 0 then v_effective / v_nihai_toplam
            else 1.0 / v_member_count
          end
        ),
        2
      )
    );
  end loop;

  insert into public.audit_events (
    actor_id, group_id, action, target_type, target_id, metadata
  ) values (
    v_uid,
    p_group_id,
    'billing_created',
    'billing_period',
    v_period.id,
    jsonb_build_object(
      'cutoff_at', v_period.cutoff_at,
      'previous_cutoff_at', case when v_prev.id is null then null else v_prev.cutoff_at end,
      'recorded_period_energy', v_kayitli_toplam,
      'bill_energy', p_bill_energy,
      'unaccounted_energy', case when p_bill_energy is null then null else v_fark end,
      'proration_policy', 'duration_overlap',
      'cutoff_policy', 'bill_date_12_europe_istanbul'
    )
  );

  return v_period;
end;
$function$
;

revoke all on function public.create_billing_period(uuid, date, numeric, numeric, text) from public, anon;
grant execute on function public.create_billing_period(uuid, date, numeric, numeric, text) to authenticated;
