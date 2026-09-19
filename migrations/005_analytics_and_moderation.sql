-- ================================================================
-- BricBook migration 005: profile analytics + admin moderation
-- Safe to re-run.
-- ================================================================

-- 1. Counter columns on studios (analytics)
alter table studios
  add column if not exists view_count           bigint not null default 0,
  add column if not exists contact_click_count  bigint not null default 0,
  add column if not exists website_click_count  bigint not null default 0,
  add column if not exists linkedin_click_count bigint not null default 0,
  add column if not exists whatsapp_click_count bigint not null default 0,
  add column if not exists email_click_count    bigint not null default 0,
  add column if not exists pdf_download_count   bigint not null default 0,
  add column if not exists qr_generate_count    bigint not null default 0,
  add column if not exists share_click_count    bigint not null default 0;

-- 2. Moderation fields
alter table studios
  add column if not exists suspended     boolean not null default false,
  add column if not exists suspended_at  timestamptz,
  add column if not exists suspended_by  uuid references profiles(id),
  add column if not exists suspend_reason text;

-- 3. Event log (optional richer trail; only writes allowed via RPC)
create table if not exists practice_events (
  id           uuid primary key default gen_random_uuid(),
  studio_id    uuid not null references studios(id) on delete cascade,
  event_type   text not null,
  session_id   text,
  referrer     text,
  ua           text,
  created_at   timestamptz not null default now()
);
create index if not exists practice_events_studio_time_idx on practice_events(studio_id, created_at desc);
create index if not exists practice_events_type_idx on practice_events(event_type);

alter table practice_events enable row level security;

drop policy if exists practice_events_read on practice_events;
drop policy if exists practice_events_write on practice_events;

/* Only firm members + admins can read their own events */
create policy practice_events_read on practice_events for select using (
  is_platform_admin() or is_studio_member(studio_id)
);
/* No direct writes — events land via the bump_studio_metric RPC */
create policy practice_events_no_direct_write on practice_events for insert with check (false);

-- 4. Bump a metric on a studio (rate-limited to 1 per event_type per session per day)
create or replace function bump_studio_metric(
  target_studio uuid,
  metric text,
  session_id text default null,
  referrer text default null,
  ua text default null
) returns void language plpgsql security definer set search_path = public as $$
declare
  col text;
  already boolean := false;
begin
  /* Rate-limit: same session + same event within last 24h counts once */
  if session_id is not null then
    select exists (
      select 1 from practice_events
      where studio_id = target_studio
        and event_type = metric
        and session_id = bump_studio_metric.session_id
        and created_at > now() - interval '24 hours'
    ) into already;
  end if;

  /* Always log the event (for granular reporting) unless it's a dupe from same session */
  if not already then
    insert into practice_events (studio_id, event_type, session_id, referrer, ua)
    values (target_studio, metric, session_id, referrer, ua);
  end if;

  /* Increment the counter column ONCE per unique session/day */
  if not already then
    col := case metric
      when 'profile_view'    then 'view_count'
      when 'contact_click'   then 'contact_click_count'
      when 'website_click'   then 'website_click_count'
      when 'linkedin_click'  then 'linkedin_click_count'
      when 'whatsapp_click'  then 'whatsapp_click_count'
      when 'email_click'     then 'email_click_count'
      when 'pdf_download'    then 'pdf_download_count'
      when 'qr_generate'     then 'qr_generate_count'
      when 'share_click'     then 'share_click_count'
      else null
    end;
    if col is not null then
      execute format('update studios set %I = %I + 1 where id = $1', col, col) using target_studio;
    end if;
  end if;
end $$;
grant execute on function bump_studio_metric(uuid, text, text, text, text) to anon, authenticated;

-- 5. Return analytics summary for the caller's studio (or given studio if admin)
create or replace function get_studio_analytics(sid uuid default null)
returns table (
  view_count bigint,
  view_count_7d bigint,
  contact_click_count bigint,
  website_click_count bigint,
  linkedin_click_count bigint,
  whatsapp_click_count bigint,
  email_click_count bigint,
  pdf_download_count bigint,
  qr_generate_count bigint,
  share_click_count bigint,
  unique_visitors bigint
) language plpgsql stable security definer set search_path = public as $$
declare
  sid_v uuid;
begin
  sid_v := coalesce(sid, (select id from studios where owner_id = auth.uid() limit 1));
  if sid_v is null then return; end if;
  if not (is_platform_admin() or is_studio_member(sid_v)) then
    raise exception 'Not authorised to view analytics for this studio';
  end if;

  return query
  select
    s.view_count,
    (select count(*) from practice_events
       where studio_id = sid_v and event_type = 'profile_view'
         and created_at > now() - interval '7 days')::bigint as view_count_7d,
    s.contact_click_count, s.website_click_count, s.linkedin_click_count,
    s.whatsapp_click_count, s.email_click_count, s.pdf_download_count,
    s.qr_generate_count, s.share_click_count,
    (select count(distinct session_id) from practice_events
       where studio_id = sid_v and event_type = 'profile_view')::bigint as unique_visitors
    from studios s where s.id = sid_v;
end $$;
grant execute on function get_studio_analytics(uuid) to authenticated;

-- 6. Admin moderation RPCs
create or replace function admin_suspend_studio(target_studio uuid, reason text default null)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_platform_admin() then raise exception 'Admin only'; end if;
  update studios
     set suspended = true,
         suspended_at = now(),
         suspended_by = auth.uid(),
         suspend_reason = reason,
         visibility = 'private'
   where id = target_studio;
end $$;
grant execute on function admin_suspend_studio(uuid, text) to authenticated;

create or replace function admin_unsuspend_studio(target_studio uuid, restore_visibility practice_visibility default 'unlisted')
returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_platform_admin() then raise exception 'Admin only'; end if;
  update studios
     set suspended = false,
         suspended_at = null,
         suspended_by = null,
         suspend_reason = null,
         visibility = restore_visibility
   where id = target_studio;
end $$;
grant execute on function admin_unsuspend_studio(uuid, practice_visibility) to authenticated;

create or replace function admin_toggle_verified(target_studio uuid, next_verified boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_platform_admin() then raise exception 'Admin only'; end if;
  update studios set verified = next_verified where id = target_studio;
end $$;
grant execute on function admin_toggle_verified(uuid, boolean) to authenticated;

comment on function bump_studio_metric is 'Rate-limited (once per session per event per 24h) counter + event log for practice profile metrics.';
comment on function get_studio_analytics is 'Return current metric snapshot for the caller''s studio (or given studio if admin/member).';
comment on function admin_suspend_studio is 'Admin: force visibility=private + mark suspended with reason.';
comment on function admin_unsuspend_studio is 'Admin: lift suspension and restore visibility.';
comment on function admin_toggle_verified is 'Admin: set the studios.verified flag on/off.';
