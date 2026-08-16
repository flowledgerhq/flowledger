-- FlowLedger Backend v1 — Usage owner completion authorization
-- Bir kullanım kaydını yalnızca onu başlatan kullanıcı kapatabilir.
-- Grup üyeleri açık kullanımı görebilir ancak başka üyenin meter_end değerini yazamaz.

create or replace function public.complete_usage(p_session_id uuid, p_meter_end numeric)
returns usage_sessions
language plpgsql
security definer
set search_path = public
as $$
declare
  v_uid uuid := auth.uid();
  v_session public.usage_sessions;
  v_row public.usage_sessions;
begin
  if v_uid is null then raise exception 'AUTH_REQUIRED'; end if;

  select * into v_session
  from public.usage_sessions
  where id = p_session_id;

  if v_session is null then raise exception 'SESSION_NOT_FOUND'; end if;

  if not exists (
    select 1 from public.group_memberships
    where group_id = v_session.group_id
      and user_id = v_uid
      and status = 'active'
  ) then
    raise exception 'NOT_A_GROUP_MEMBER';
  end if;

  if v_session.user_id <> v_uid then
    raise exception 'SESSION_NOT_OWNER';
  end if;

  if v_session.status not in ('armed','active') then
    raise exception 'SESSION_NOT_OPEN';
  end if;

  if p_meter_end is null
     or (v_session.meter_start is not null and p_meter_end < v_session.meter_start) then
    raise exception 'INVALID_METER_END';
  end if;

  update public.usage_sessions
  set meter_end = p_meter_end,
      energy_used = case when meter_start is not null then p_meter_end - meter_start else null end,
      ended_at = now(),
      status = 'completed'
  where id = p_session_id
  returning * into v_row;

  insert into public.audit_events(actor_id, group_id, action, target_type, target_id)
  values(v_uid, v_row.group_id, 'usage_completed', 'usage_session', v_row.id);

  return v_row;
end;
$$;

revoke all on function public.complete_usage(uuid, numeric) from public, anon;
grant execute on function public.complete_usage(uuid, numeric) to authenticated;
