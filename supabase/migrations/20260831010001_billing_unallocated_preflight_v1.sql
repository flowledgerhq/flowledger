-- FlowLedger — bill-date-aware billing preflight + explicit unallocated state
-- Keeps bill_date 12:00 Europe/Istanbul as the immutable accounting boundary.
-- Billing policy is unchanged; this migration adds (a) a server-side preflight
-- RPC sharing one proration implementation with create_billing_period(), and
-- (b) an explicit finalized/unallocated state on billing_periods.

-- ============================================================
-- 1) billing_periods.status
-- ============================================================

alter table public.billing_periods
  add column if not exists status text;

-- Backfill legacy rows from the presence of allocations.
update public.billing_periods bp
set status = case
  when exists (
    select 1 from public.allocations a
    where a.billing_period_id = bp.id
  ) then 'finalized'
  else 'unallocated'
end
where status is null;

-- Default is the conservative value: a row that somehow lands here without an
-- explicit status must not be silently presented as a completed distribution.
alter table public.billing_periods
  alter column status set default 'unallocated',
  alter column status set not null;

alter table public.billing_periods
  drop constraint if exists billing_periods_status_check;
alter table public.billing_periods
  add constraint billing_periods_status_check
  check (status in ('finalized', 'unallocated'));

-- ============================================================
-- 2) Single source of truth for window proration
-- ============================================================
-- Both preview_billing_period() and create_billing_period() call this, so the
-- preflight figure and the figure that drives allocations can never drift.
-- Window semantics: (p_window_start, p_window_end], duration-overlap prorated.

create or replace function public._billing_window_usage(
  p_group_id uuid,
  p_window_start timestamptz,
  p_window_end timestamptz
)
returns table (user_id uuid, energy numeric)
language sql
stable
set search_path = public
as $function$
  select p.user_id, sum(p.prorated_energy)::numeric as energy
  from (
    select
      s.user_id,
      case
        when s.ended_at = s.started_at then
          -- Zero-duration session: belongs wholly to the window containing it.
          case
            when s.started_at > p_window_start and s.started_at <= p_window_end
              then s.energy_used
            else 0
          end
        else
          s.energy_used
          * greatest(
              0,
              extract(epoch from (
                least(s.ended_at, p_window_end)
                - greatest(s.started_at, p_window_start)
              ))
            )
          / extract(epoch from (s.ended_at - s.started_at))
      end as prorated_energy
    from public.usage_sessions s
    where s.group_id = p_group_id
      and s.status = 'completed'
      and s.energy_used is not null
      and s.started_at <= p_window_end
      and s.ended_at > p_window_start
  ) p
  where p.prorated_energy > 0
  group by p.user_id;
$function$;

-- Internal helper: only the SECURITY DEFINER RPCs below may call it.
revoke all on function public._billing_window_usage(uuid, timestamptz, timestamptz)
  from public, anon, authenticated;

-- ============================================================
-- 3) preview_billing_period()
-- ============================================================

create or replace function public.preview_billing_period(
  p_group_id uuid,
  p_bill_date date
)
returns table (
  cutoff_at timestamptz,
  previous_cutoff_at timestamptz,
  recorded_period_energy numeric,
  recorded_user_count integer,
  open_usage_crosses_cutoff boolean,
  cutoff_reached boolean,
  later_period_exists boolean
)
language plpgsql
stable
security definer
set search_path = public
as $function$
declare
  v_uid uuid := auth.uid();
  v_prev public.billing_periods;
  v_window_start timestamptz;
  v_window_end timestamptz;
  v_energy numeric;
  v_users integer;
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

  v_window_end := (p_bill_date::timestamp + interval '12 hours') at time zone 'Europe/Istanbul';

  -- Previous boundary is the newest cutoff strictly before this one, regardless
  -- of that period's status: an unallocated period still fixes the boundary.
  select bp.* into v_prev
  from public.billing_periods bp
  where bp.group_id = p_group_id
    and bp.cutoff_at < v_window_end
  order by bp.cutoff_at desc
  limit 1;

  v_window_start := coalesce(v_prev.cutoff_at, '-infinity'::timestamptz);

  select coalesce(sum(u.energy), 0)::numeric, count(*)::integer
  into v_energy, v_users
  from public._billing_window_usage(p_group_id, v_window_start, v_window_end) u;

  return query select
    v_window_end,
    v_prev.cutoff_at,
    v_energy,
    v_users,
    exists (
      select 1
      from public.usage_sessions s
      where s.group_id = p_group_id
        and s.status in ('active','armed')
        and s.started_at <= v_window_end
    ),
    (v_window_end <= now()),
    exists (
      select 1
      from public.billing_periods bp
      where bp.group_id = p_group_id
        and bp.cutoff_at > v_window_end
    );
end;
$function$;

revoke all on function public.preview_billing_period(uuid, date) from public, anon;
grant execute on function public.preview_billing_period(uuid, date) to authenticated;

-- ============================================================
-- 4) create_billing_period()
-- ============================================================
-- Unchanged policy: bill_date 12:00 Europe/Istanbul cutoff, duration-overlap
-- proration, immutable allocation snapshot. New: explicit status, and a guard
-- against inserting a period behind an existing one (which would allocate the
-- same usage twice).

create or replace function public.create_billing_period(
  p_group_id uuid,
  p_bill_date date,
  p_total_amount numeric,
  p_bill_energy numeric,
  p_allocation_method text
)
returns public.billing_periods
language plpgsql
security definer
set search_path = public
as $function$
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
  v_status text;
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

  if v_window_end > now() then
    raise exception 'BILLING_CUTOFF_NOT_REACHED';
  end if;

  -- A period may be entered late, but never behind an existing boundary: that
  -- would re-allocate usage already settled by the later period.
  if exists (
    select 1 from public.billing_periods bp
    where bp.group_id = p_group_id
      and bp.cutoff_at > v_window_end
  ) then
    raise exception 'BILLING_PERIOD_OUT_OF_ORDER';
  end if;

  select * into v_prev
  from public.billing_periods
  where group_id = p_group_id
    and cutoff_at < v_window_end
  order by cutoff_at desc
  limit 1;

  v_window_start := coalesce(v_prev.cutoff_at, '-infinity'::timestamptz);

  if exists (
    select 1
    from public.usage_sessions s
    where s.group_id = p_group_id
      and s.status in ('active','armed')
      and s.started_at <= v_window_end
  ) then
    raise exception 'OPEN_USAGE_CROSSES_BILLING_CUTOFF';
  end if;

  -- Compute the exact period usage before inserting the immutable billing row,
  -- so a zero-usage invoice can be persisted explicitly as unallocated.
  select coalesce(sum(u.energy), 0), count(*)
  into v_kayitli_toplam, v_member_count
  from public._billing_window_usage(p_group_id, v_window_start, v_window_end) u;

  v_status := case when v_member_count = 0 then 'unallocated' else 'finalized' end;

  insert into public.billing_periods (
    group_id, bill_date, cutoff_at, total_amount, bill_energy, allocation_method, status
  ) values (
    p_group_id, p_bill_date, v_window_end, p_total_amount, p_bill_energy, p_allocation_method, v_status
  )
  returning * into v_period;

  if v_member_count = 0 then
    insert into public.audit_events (
      actor_id, group_id, action, target_type, target_id, metadata
    ) values (
      v_uid, p_group_id, 'billing_created', 'billing_period', v_period.id,
      jsonb_build_object(
        'cutoff_at', v_period.cutoff_at,
        'previous_cutoff_at', v_prev.cutoff_at,
        'recorded_period_energy', 0,
        'bill_energy', p_bill_energy,
        'billing_status', 'unallocated',
        'proration_policy', 'duration_overlap',
        'cutoff_policy', 'bill_date_12_europe_istanbul'
      )
    );
    return v_period;
  end if;

  if p_bill_energy is not null and v_kayitli_toplam > 0 then
    v_fark := p_bill_energy - v_kayitli_toplam;
  end if;

  if v_fark != 0 and v_kayitli_toplam > 0 then
    v_nihai_toplam := v_kayitli_toplam + v_fark;
  else
    v_nihai_toplam := v_kayitli_toplam;
  end if;

  for r in (
    select u.user_id, u.energy
    from public._billing_window_usage(p_group_id, v_window_start, v_window_end) u
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
      'previous_cutoff_at', v_prev.cutoff_at,
      'recorded_period_energy', v_kayitli_toplam,
      'bill_energy', p_bill_energy,
      'unaccounted_energy', case when p_bill_energy is null then null else v_fark end,
      'billing_status', 'finalized',
      'proration_policy', 'duration_overlap',
      'cutoff_policy', 'bill_date_12_europe_istanbul'
    )
  );

  return v_period;
end;
$function$;

revoke all on function public.create_billing_period(uuid, date, numeric, numeric, text) from public, anon;
grant execute on function public.create_billing_period(uuid, date, numeric, numeric, text) to authenticated;
