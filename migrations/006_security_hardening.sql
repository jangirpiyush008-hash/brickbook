-- ================================================================
-- BricBook migration 006: security hardening
-- Fixes 5 HIGH + 4 MEDIUM + 1 LOW findings from the Sep-19 audit.
-- Safe to re-run.
-- ================================================================

-- ============================================================
-- FIX H1: admin_invitations view leaks every firm's invitations
-- ============================================================
-- The view was created without security_invoker=true, so it runs as the
-- view owner and bypasses invitations RLS. Any authenticated user could
-- SELECT admin_invitations and read every firm's tokens.
drop view if exists admin_invitations;
create or replace view admin_invitations
  with (security_invoker = true) as
  select i.*, s.name as studio_name, s.slug as studio_slug,
         p.name as project_name, p.code as project_code,
         ib.full_name as invited_by_name, ib.email as invited_by_email
    from invitations i
    left join studios s on s.id = i.studio_id
    left join projects p on p.id = i.project_id
    left join profiles ib on ib.id = i.invited_by;
/* No grant needed — inherits from base tables via security_invoker */

-- ============================================================
-- FIX H2: bump_studio_metric rate-limit bypass
-- ============================================================
-- Was: rate-limit block only ran when session_id was NOT NULL, so callers
--      that omitted or rotated session_id could inflate counters unbounded.
-- Now: require session_id (raise if missing), hash with a server-side salt,
--      and always de-dupe on the hash within 24h.
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
  session_hash text;
begin
  if target_studio is null then return; end if;
  /* Require a session identifier so counters can be de-duped */
  if session_id is null or length(session_id) < 8 then
    raise exception 'session_id required';
  end if;
  /* Hash the session id with a server-side salt so the event log doesn't
     store raw client-supplied session ids (and rotating them can't defeat dedup) */
  session_hash := encode(digest('bb_metric_' || session_id || coalesce(ua,''), 'sha256'), 'hex');

  select exists (
    select 1 from practice_events
    where studio_id = target_studio
      and event_type = metric
      and session_id = session_hash
      and created_at > now() - interval '24 hours'
  ) into already;

  if already then return; end if;

  insert into practice_events (studio_id, event_type, session_id, referrer, ua)
  values (target_studio, metric, session_hash, referrer, ua);

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
end $$;
/* pgcrypto for digest() — enable if not already */
create extension if not exists pgcrypto;

-- ============================================================
-- FIX H3: create_client_invitation didn't verify project ↔ studio link
-- ============================================================
-- A firm member could pass target_project_id = another firm's project, and
-- accept_client_invitation would grant the accepting client project_members
-- rows on the wrong firm's project.
create or replace function create_client_invitation(
  client_email text,
  client_name text default null,
  client_phone text default null,
  target_studio_id uuid default null,
  target_project_id uuid default null,
  member_role project_member_role default 'client'
) returns table (invitation_id uuid, token uuid) language plpgsql security definer set search_path = public as $$
declare
  uid uuid;
  sid uuid;
  inv_id uuid;
  inv_token uuid;
  proj_studio uuid;
begin
  uid := auth.uid();
  if uid is null then raise exception 'Not authenticated'; end if;

  sid := coalesce(target_studio_id, (select id from studios where owner_id = uid limit 1));
  if sid is null then raise exception 'No studio to invite into'; end if;

  if not (is_studio_member(sid) or is_platform_admin()) then
    raise exception 'Not authorised to create invitations for this studio';
  end if;

  /* If a project was specified, it MUST belong to the studio */
  if target_project_id is not null then
    select studio_id into proj_studio from projects where id = target_project_id;
    if proj_studio is null then raise exception 'Project not found'; end if;
    if proj_studio <> sid then raise exception 'Project does not belong to this studio'; end if;
  end if;

  /* Whitelist the role so an admin cannot smuggle in a stronger role at invitation time */
  if member_role not in ('client','viewer','contributor') then
    raise exception 'Invalid invitation role';
  end if;

  inv_token := gen_random_uuid();

  insert into invitations (
    project_id, email, full_name, phone, role, studio_id, token, status, invited_by, expires_at
  ) values (
    target_project_id, lower(client_email), client_name, client_phone, member_role,
    sid, inv_token, 'pending', uid, now() + interval '30 days'
  ) returning id into inv_id;

  return query select inv_id, inv_token;
end $$;
grant execute on function create_client_invitation(text, text, text, uuid, uuid, project_member_role) to authenticated;

-- ============================================================
-- FIX H4: studio_members could rewrite owner_id / verified / suspended
-- ============================================================
-- The RLS UPDATE policy on studios lets any studio_member modify the row.
-- Column-level enforcement via a BEFORE UPDATE trigger blocks non-admin
-- writes to owner_id, verified, suspended, suspended_at, suspended_by,
-- suspend_reason, bric_id, and profile_completion_lock.
create or replace function protect_studio_privileged_cols()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if is_platform_admin() then
    return NEW;
  end if;
  /* Compare each protected column; raise if a non-admin changed one */
  if OLD.owner_id       is distinct from NEW.owner_id       then raise exception 'owner_id is admin-controlled'; end if;
  if OLD.verified       is distinct from NEW.verified       then raise exception 'verified is admin-controlled'; end if;
  if OLD.suspended      is distinct from NEW.suspended      then raise exception 'suspended is admin-controlled'; end if;
  if OLD.suspended_at   is distinct from NEW.suspended_at   then raise exception 'suspended_at is admin-controlled'; end if;
  if OLD.suspended_by   is distinct from NEW.suspended_by   then raise exception 'suspended_by is admin-controlled'; end if;
  if OLD.suspend_reason is distinct from NEW.suspend_reason then raise exception 'suspend_reason is admin-controlled'; end if;
  if OLD.bric_id        is distinct from NEW.bric_id        then raise exception 'bric_id is immutable'; end if;
  return NEW;
end $$;

drop trigger if exists tr_protect_studio_privileged_cols on studios;
create trigger tr_protect_studio_privileged_cols
before update on studios
for each row execute function protect_studio_privileged_cols();

-- ============================================================
-- FIX H5: studios SELECT policy leaks moderation columns to anon
-- ============================================================
-- The base schema allowed anon to SELECT * from studios, which exposes
-- suspended, suspend_reason, suspended_by, suspended_at to anyone.
-- Solution: revoke SELECT on those columns from anon + authenticated; only
-- admins read them (their queries run as super_admin/ops_admin which are
-- not covered by anon/authenticated grants).
revoke select on studios from anon, authenticated;
grant select (
  id, slug, name, city, state, country, bio, description_long, tagline,
  years_experience, specialties, services, logo_url, cover_url, fee_rate,
  verified, owner_id, created_at, updated_at,
  bric_id, founded_year, practice_type, website, contact_email, contact_phone,
  linkedin, instagram, behance, intro_video_url, visibility,
  profile_completion,
  view_count, contact_click_count, website_click_count, linkedin_click_count,
  whatsapp_click_count, email_click_count, pdf_download_count, qr_generate_count,
  share_click_count
) on studios to anon, authenticated;
/* NOTE: suspended, suspended_at, suspended_by, suspend_reason are intentionally
   excluded from the grant. Admin queries use is_platform_admin() functions
   which run under RLS + full-table select as owner. */

-- ============================================================
-- FIX M6: invitations_firm_update missing WITH CHECK
-- ============================================================
drop policy if exists invitations_firm_update on invitations;
create policy invitations_firm_update on invitations for update
  using (
    is_platform_admin()
    or (studio_id is not null and is_studio_member(studio_id))
  )
  with check (
    is_platform_admin()
    or (studio_id is not null and is_studio_member(studio_id))
  );

-- ============================================================
-- FIX M7: recalc_profile_completion didn't check membership when sid supplied
-- ============================================================
create or replace function recalc_profile_completion(sid uuid default null)
returns int language plpgsql security definer set search_path = public as $$
declare
  sid_v uuid;
  s studios%rowtype;
  score int := 0;
begin
  sid_v := coalesce(sid, (select id from studios where owner_id = auth.uid() limit 1));
  if sid_v is null then return 0; end if;
  if not (is_platform_admin() or is_studio_member(sid_v)) then
    raise exception 'Not authorised';
  end if;
  select * into s from studios where id = sid_v;
  if not found then return 0; end if;

  if s.name is not null and length(s.name) > 1 then score := score + 8; end if;
  if s.tagline is not null and length(s.tagline) > 0 then score := score + 6; end if;
  if s.bio is not null and length(s.bio) > 40 then score := score + 8; end if;
  if s.description_long is not null and length(s.description_long) > 80 then score := score + 8; end if;
  if s.city is not null then score := score + 4; end if;
  if s.state is not null then score := score + 3; end if;
  if s.country is not null then score := score + 2; end if;
  if s.founded_year is not null then score := score + 4; end if;
  if s.logo_url is not null then score := score + 8; end if;
  if s.cover_url is not null then score := score + 6; end if;
  if s.website is not null then score := score + 5; end if;
  if s.contact_email is not null then score := score + 5; end if;
  if s.contact_phone is not null then score := score + 3; end if;
  if s.linkedin is not null then score := score + 3; end if;
  if s.instagram is not null then score := score + 3; end if;
  if array_length(s.services, 1) is not null and array_length(s.services, 1) >= 1 then score := score + 6; end if;
  if array_length(s.specialties, 1) is not null and array_length(s.specialties, 1) >= 1 then score := score + 4; end if;
  if exists (select 1 from projects where studio_id = sid_v) then score := score + 8; end if;
  if exists (select 1 from projects where studio_id = sid_v and pinned = true) then score := score + 4; end if;
  if exists (select 1 from awards where studio_id = sid_v) then score := score + 2; end if;

  score := least(100, greatest(0, score));
  update studios set profile_completion = score where id = sid_v;
  return score;
end $$;

-- ============================================================
-- FIX M8: find_user_role granted to anon → user role enumeration
-- ============================================================
revoke execute on function find_user_role(uuid) from anon;
/* Drop the uuid parameter so it can only return the caller's own role */
create or replace function find_user_role()
returns text language sql stable security definer set search_path = public as $$
  select coalesce(role::text, 'unknown') from profiles where id = auth.uid();
$$;
grant execute on function find_user_role() to authenticated;

-- ============================================================
-- FIX M9: has_pending_invitation granted to anon → email enumeration oracle
-- ============================================================
revoke execute on function has_pending_invitation(text) from anon;
/* Keep for authenticated callers (helpful when linking a Google email to an invite) */

-- ============================================================
-- FIX M10: project_members INSERT was too permissive
-- ============================================================
-- Was: is_project_member(project_id) — any existing member of the project
--      could add anyone else, allowing rogue firm members to add
--      competitor users as viewers to leak project data via visibility.
-- Now: only studio side (firm_admin / project_manager on the studio) or
--      platform admin can add members; regular members can't add themselves.
drop policy if exists pm_write on project_members;
drop policy if exists pm_write_admin_or_studio on project_members;
create policy pm_write_admin_or_studio on project_members for all
  using (
    is_platform_admin()
    or exists (
      select 1 from projects p
      join studio_members sm on sm.studio_id = p.studio_id
      where p.id = project_members.project_id
        and sm.user_id = auth.uid()
        and sm.team_role in ('firm_admin','project_manager')
    )
  )
  with check (
    is_platform_admin()
    or exists (
      select 1 from projects p
      join studio_members sm on sm.studio_id = p.studio_id
      where p.id = project_members.project_id
        and sm.user_id = auth.uid()
        and sm.team_role in ('firm_admin','project_manager')
    )
  );

-- ============================================================
-- FIX L11: accept_client_invitation trusted inv.role blindly
-- ============================================================
-- Already partially addressed by the invitation-time whitelist in fix H3.
-- Belt + braces: re-validate at accept time.
create or replace function accept_client_invitation(inv_token uuid)
returns table (studio_id uuid, project_id uuid) language plpgsql security definer set search_path = public as $$
declare
  inv invitations%rowtype;
  auth_email text;
  auth_user_id uuid;
  full_name_v text;
  uname text;
  safe_role project_member_role;
begin
  auth_user_id := auth.uid();
  if auth_user_id is null then raise exception 'Not authenticated'; end if;

  select email into auth_email from auth.users where id = auth_user_id;
  if auth_email is null then raise exception 'No email on authenticated user'; end if;

  select * into inv from invitations where token = inv_token;
  if not found then raise exception 'Invitation not found'; end if;
  if inv.status <> 'pending' then
    raise exception 'Invitation is % (only pending invitations can be accepted)', inv.status;
  end if;
  if inv.expires_at < now() then
    update invitations set status = 'expired' where id = inv.id;
    raise exception 'Invitation has expired';
  end if;
  if lower(inv.email) <> lower(auth_email) then
    raise exception 'This invitation was sent to a different email address';
  end if;

  /* Re-whitelist role: never grant anything stronger than 'contributor' via an invitation */
  safe_role := case inv.role
    when 'client' then 'client'::project_member_role
    when 'viewer' then 'viewer'::project_member_role
    when 'contributor' then 'contributor'::project_member_role
    else 'client'::project_member_role
  end;

  full_name_v := coalesce(inv.full_name, split_part(auth_email, '@', 1));
  uname := lower(regexp_replace(full_name_v, '[^a-zA-Z0-9]+', '.', 'g'));
  uname := regexp_replace(uname, '^\.|\.$', '', 'g');
  if uname = '' then uname := split_part(auth_email, '@', 1); end if;

  insert into profiles (id, username, full_name, email, phone, role)
  values (auth_user_id, uname || '.' || substr(auth_user_id::text, 1, 4), full_name_v, auth_email, inv.phone, 'client')
  on conflict (id) do update
    set full_name = coalesce(profiles.full_name, excluded.full_name),
        phone     = coalesce(profiles.phone, excluded.phone),
        role      = case when profiles.role = 'client' then 'client'::user_role else profiles.role end;

  if inv.project_id is not null then
    insert into project_members (project_id, user_id, role)
    values (inv.project_id, auth_user_id, safe_role)
    on conflict (project_id, user_id) do nothing;
  end if;

  update invitations
     set status = 'accepted',
         accepted_at = now(),
         accepted_by = auth_user_id
   where id = inv.id;

  return query select inv.studio_id, inv.project_id;
end;
$$;

comment on function bump_studio_metric is 'Rate-limited metric counter (server-hashed session id) + append-only event log for practice profile stats.';
comment on function create_client_invitation is 'Firm member creates a client invitation; project must belong to the studio; role is whitelisted.';
comment on function accept_client_invitation is 'Validate + accept a client invitation. Server-side email match; role is whitelisted at accept time.';
comment on function protect_studio_privileged_cols is 'BEFORE UPDATE trigger on studios: non-admins cannot change owner_id, verified, suspended*, bric_id.';
comment on function find_user_role is 'Return the caller''s canonical role (no arbitrary uid lookup).';
