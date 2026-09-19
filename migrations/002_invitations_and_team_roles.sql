-- ================================================================
-- BricBook migration 002: invitation flow + team roles
-- Run this ONCE in the Supabase SQL editor after the base schema.
-- Idempotent (safe to re-run).
-- ================================================================

-- 1. Team-role enum for architect firm members
do $$ begin
  create type team_role as enum ('firm_admin','project_manager','designer','viewer');
exception when duplicate_object then null; end $$;

-- 2. Extend studio_members with the finer permission role
alter table studio_members
  add column if not exists team_role team_role not null default 'firm_admin';

-- 3. Ensure every firm has at least one admin
-- (Backfill: existing rows that were studio_owner get firm_admin)
update studio_members
   set team_role = 'firm_admin'
 where role = 'studio_owner' and team_role = 'firm_admin';

-- 4. Extend invitations: token, status, expiry
do $$ begin
  create type invitation_status as enum ('pending','accepted','expired','revoked');
exception when duplicate_object then null; end $$;

alter table invitations
  add column if not exists token uuid not null default gen_random_uuid(),
  add column if not exists status invitation_status not null default 'pending',
  add column if not exists expires_at timestamptz not null default (now() + interval '30 days'),
  add column if not exists studio_id uuid references studios(id) on delete cascade,
  add column if not exists full_name text,
  add column if not exists phone text,
  add column if not exists accepted_at timestamptz,
  add column if not exists accepted_by uuid references profiles(id);

create unique index if not exists invitations_token_idx on invitations(token);
create index if not exists invitations_email_status_idx on invitations(email, status);

-- 5. Helper: find the caller's canonical role for routing decisions
create or replace function find_user_role(uid uuid default auth.uid())
returns text language sql stable security definer set search_path = public as $$
  select coalesce(role::text, 'unknown') from profiles where id = uid;
$$;
grant execute on function find_user_role(uuid) to anon, authenticated;

-- 6. Helper: check if an email has a pending invitation
create or replace function has_pending_invitation(check_email text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from invitations
    where lower(email) = lower(check_email)
      and status = 'pending'
      and expires_at > now()
  );
$$;
grant execute on function has_pending_invitation(text) to anon, authenticated;

-- 7. Core RPC: accept a client invitation
--    - Validates token + expiry + status
--    - Validates the caller's authenticated email matches invitation.email
--    - Creates or updates the profile row with role='client' + city/phone
--    - Adds them to project_members for every project the firm has that
--      references this invitation (via invitations.project_id when set)
--    - Marks the invitation accepted
--    Returns the studio_id the client was linked to.
create or replace function accept_client_invitation(inv_token uuid)
returns table (studio_id uuid, project_id uuid) language plpgsql security definer set search_path = public as $$
declare
  inv invitations%rowtype;
  auth_email text;
  auth_user_id uuid;
  full_name_v text;
  uname text;
begin
  auth_user_id := auth.uid();
  if auth_user_id is null then
    raise exception 'Not authenticated';
  end if;

  select email into auth_email from auth.users where id = auth_user_id;
  if auth_email is null then
    raise exception 'No email on authenticated user';
  end if;

  select * into inv from invitations where token = inv_token;
  if not found then
    raise exception 'Invitation not found';
  end if;
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

  full_name_v := coalesce(inv.full_name, split_part(auth_email, '@', 1));
  uname := lower(regexp_replace(full_name_v, '[^a-zA-Z0-9]+', '.', 'g'));
  uname := regexp_replace(uname, '^\.|\.$', '', 'g');
  if uname = '' then uname := split_part(auth_email, '@', 1); end if;

  -- Upsert profile (client role)
  insert into profiles (id, username, full_name, email, phone, role)
  values (auth_user_id, uname || '.' || substr(auth_user_id::text, 1, 4), full_name_v, auth_email, inv.phone, 'client')
  on conflict (id) do update
    set full_name = coalesce(profiles.full_name, excluded.full_name),
        phone     = coalesce(profiles.phone, excluded.phone),
        role      = case when profiles.role = 'client' then 'client'::user_role else profiles.role end;

  -- If invitation references a project, add them as a project member
  if inv.project_id is not null then
    insert into project_members (project_id, user_id, role)
    values (inv.project_id, auth_user_id, inv.role)
    on conflict (project_id, user_id) do nothing;
  end if;

  -- Also add them as project member for every project of the invited firm
  -- (so an invited client can see all of that firm's projects they're on)
  if inv.studio_id is not null then
    insert into project_members (project_id, user_id, role)
    select p.id, auth_user_id, coalesce(inv.role, 'client')
      from projects p
     where p.studio_id = inv.studio_id
       and p.client_id = auth_user_id
    on conflict (project_id, user_id) do nothing;
  end if;

  -- Mark accepted
  update invitations
     set status = 'accepted',
         accepted_at = now(),
         accepted_by = auth_user_id
   where id = inv.id;

  return query select inv.studio_id, inv.project_id;
end;
$$;
grant execute on function accept_client_invitation(uuid) to authenticated;

-- 8. RLS for invitations
alter table invitations enable row level security;

drop policy if exists invitations_all on invitations;

-- Firm members can read/create/revoke invitations for their studio
create policy invitations_firm_select on invitations for select using (
  is_platform_admin()
  or (studio_id is not null and is_studio_member(studio_id))
  or (invited_by = auth.uid())
);
create policy invitations_firm_insert on invitations for insert with check (
  is_platform_admin()
  or (studio_id is not null and is_studio_member(studio_id))
);
create policy invitations_firm_update on invitations for update using (
  is_platform_admin()
  or (studio_id is not null and is_studio_member(studio_id))
);

-- Anonymous / anyone can look up a specific invitation BY TOKEN only, via a security-definer function
create or replace function get_invitation_by_token(inv_token uuid)
returns table (
  id uuid, email text, full_name text, phone text,
  studio_id uuid, studio_name text, studio_slug text,
  project_id uuid, project_name text,
  role project_member_role, status invitation_status,
  expires_at timestamptz
) language sql stable security definer set search_path = public as $$
  select i.id, i.email, i.full_name, i.phone,
         i.studio_id, s.name, s.slug,
         i.project_id, p.name,
         i.role, i.status, i.expires_at
    from invitations i
    left join studios s on s.id = i.studio_id
    left join projects p on p.id = i.project_id
   where i.token = inv_token;
$$;
grant execute on function get_invitation_by_token(uuid) to anon, authenticated;

-- 9. Convenience view for admin panel: invitations with joined firm/project names
create or replace view admin_invitations as
  select i.*, s.name as studio_name, s.slug as studio_slug,
         p.name as project_name, p.code as project_code,
         ib.full_name as invited_by_name, ib.email as invited_by_email
    from invitations i
    left join studios s on s.id = i.studio_id
    left join projects p on p.id = i.project_id
    left join profiles ib on ib.id = i.invited_by;

grant select on admin_invitations to authenticated;

-- 10. Allow controlled self-upgrade from client -> studio_owner (for new firm registration)
--     Everything else still requires platform admin.
create or replace function prevent_role_escalation()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if OLD.role is distinct from NEW.role then
    if is_platform_admin() then
      return NEW;
    end if;
    -- Allow user to upgrade themselves from client to studio_owner (firm registration)
    if OLD.role = 'client' and NEW.role = 'studio_owner' and auth.uid() = NEW.id then
      return NEW;
    end if;
    raise exception 'Role changes require admin privileges';
  end if;
  return NEW;
end $$;

-- 11. RPC: register a new user as an architect firm
--     Upgrades their profile role + creates their studio row.
create or replace function register_as_architect_firm(firm_name text default null, city_v text default 'Mumbai')
returns uuid language plpgsql security definer set search_path = public as $$
declare
  uid uuid;
  user_email text;
  slug_v text;
  sid uuid;
  existing_sid uuid;
begin
  uid := auth.uid();
  if uid is null then raise exception 'Not authenticated'; end if;

  -- If the user already owns a studio, return that
  select id into existing_sid from studios where owner_id = uid limit 1;
  if existing_sid is not null then
    return existing_sid;
  end if;

  select email into user_email from auth.users where id = uid;

  -- Upgrade role (client -> studio_owner) via trigger's self-upgrade rule
  update profiles set role = 'studio_owner' where id = uid;

  -- Build a slug: firm_name (kebab-case) + first 4 chars of uid for uniqueness
  slug_v := lower(regexp_replace(coalesce(firm_name, split_part(user_email, '@', 1)), '[^a-zA-Z0-9]+', '-', 'g'));
  slug_v := regexp_replace(slug_v, '^-+|-+$', '', 'g');
  if slug_v = '' then slug_v := 'studio'; end if;
  slug_v := slug_v || '-' || substr(uid::text, 1, 4);

  insert into studios (slug, name, owner_id, city)
  values (slug_v, coalesce(firm_name, split_part(user_email, '@', 1) || '’s studio'), uid, city_v)
  returning id into sid;

  insert into studio_members (studio_id, user_id, role, team_role)
  values (sid, uid, 'studio_owner', 'firm_admin')
  on conflict do nothing;

  return sid;
end $$;
grant execute on function register_as_architect_firm(text, text) to authenticated;

-- 12. RPC: Firm creates a client invitation
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
begin
  uid := auth.uid();
  if uid is null then raise exception 'Not authenticated'; end if;

  -- Resolve studio: given, or user's own
  sid := coalesce(target_studio_id, (select id from studios where owner_id = uid limit 1));
  if sid is null then raise exception 'No studio to invite into'; end if;

  -- Caller must be a member of that studio, or a platform admin
  if not (is_studio_member(sid) or is_platform_admin()) then
    raise exception 'Not authorised to create invitations for this studio';
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

-- 13. RPC: Revoke a pending invitation
create or replace function revoke_invitation(inv_id uuid)
returns void language plpgsql security definer set search_path = public as $$
declare
  inv invitations%rowtype;
begin
  select * into inv from invitations where id = inv_id;
  if not found then raise exception 'Invitation not found'; end if;
  if not (is_platform_admin() or (inv.studio_id is not null and is_studio_member(inv.studio_id)) or inv.invited_by = auth.uid()) then
    raise exception 'Not authorised to revoke this invitation';
  end if;
  update invitations set status = 'revoked' where id = inv_id;
end $$;
grant execute on function revoke_invitation(uuid) to authenticated;

-- 14. Comments
comment on function accept_client_invitation is 'Atomically validate + activate a client invitation. Requires authenticated caller; email must match invitation.email.';
comment on function get_invitation_by_token is 'Public lookup of an invitation by unique token, used to render the /client/invite/<token> landing page.';
comment on function find_user_role is 'Returns the caller''s (or given user''s) canonical role, used for post-login routing.';
comment on function has_pending_invitation is 'True if this email has any pending, unexpired invitation.';
comment on function register_as_architect_firm is 'Upgrade the authenticated caller from client to studio_owner and create their studio.';
comment on function create_client_invitation is 'Firm member creates a client invitation. Returns the unique token used in /client/invite/<token>.';
comment on function revoke_invitation is 'Mark a pending invitation as revoked.';
