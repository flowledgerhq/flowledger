-- FlowLedger Backend v1 — Tek Açık Kullanım Garantisi
-- Aynı kuyu/grup için aynı anda yalnızca bir active/armed usage_session olabilir.
-- Frontend çift tıklama korumasına güvenilmez; invariant DB seviyesindedir.

create unique index if not exists idx_usage_sessions_one_open_per_group
  on public.usage_sessions(group_id)
  where status in ('active','armed');

create or replace function public.start_manual_usage(p_group_id uuid, p_meter_start numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_row public.usage_sessions;
  v_prev public.usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;
  if not exists (
    select 1 from public.group_memberships
    where group_id=p_group_id and user_id=v_uid and status='active'
  ) then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;
  if p_meter_start is null or p_meter_start < 0 then raise exception 'INVALID_METER_START'; end if;

  -- Friendly fast-path. The unique partial index below remains the real
  -- concurrency guarantee if two devices race past this check.
  if exists (
    select 1 from public.usage_sessions
    where group_id=p_group_id and status in ('active','armed')
  ) then
    raise exception 'OPEN_USAGE_ALREADY_EXISTS';
  end if;

  select * into v_prev
  from public.usage_sessions
  where group_id=p_group_id and status='completed' and meter_end is not null
  order by completion_seq desc
  limit 1;

  if v_prev.id is not null and p_meter_start < v_prev.meter_end then
    raise exception 'METER_START_BELOW_PREVIOUS_END'
      using detail=format('previous_end=%s observed_start=%s',v_prev.meter_end,p_meter_start),
            hint='Yeni manuel açılış değeri son tamamlanmış kapanış değerinden küçük olamaz.';
  end if;

  begin
    insert into public.usage_sessions(
      group_id,user_id,status,source,meter_start,started_at,
      previous_session_id,expected_meter_start
    ) values (
      p_group_id,v_uid,'active','manual',p_meter_start,now(),
      v_prev.id,v_prev.meter_end
    ) returning * into v_row;
  exception when unique_violation then
    raise exception 'OPEN_USAGE_ALREADY_EXISTS';
  end;

  insert into public.audit_events(actor_id,group_id,action,target_type,target_id,metadata)
  values(
    v_uid,p_group_id,'usage_started','usage_session',v_row.id,
    jsonb_strip_nulls(jsonb_build_object(
      'previous_session_id',v_row.previous_session_id,
      'expected_meter_start',v_row.expected_meter_start,
      'observed_meter_start',v_row.meter_start,
      'meter_gap',v_row.meter_gap
    ))
  );

  if v_row.meter_gap is not null and v_row.meter_gap <> 0 then
    insert into public.audit_events(actor_id,group_id,action,target_type,target_id,metadata)
    values(
      v_uid,p_group_id,'meter_discrepancy_detected','usage_session',v_row.id,
      jsonb_build_object(
        'previous_session_id',v_row.previous_session_id,
        'expected_meter_start',v_row.expected_meter_start,
        'observed_meter_start',v_row.meter_start,
        'meter_gap',v_row.meter_gap
      )
    );
  end if;

  return v_row;
end;
$$;

revoke all on function public.start_manual_usage(uuid, numeric) from public, anon;
grant execute on function public.start_manual_usage(uuid, numeric) to authenticated;
