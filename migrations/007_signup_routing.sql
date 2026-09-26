-- ================================================================
-- BricBook migration 007: signup routing (auto-accept invitations)
-- Every new sign-in whose email matches a pending invitation is
-- auto-attached to that firm/project as a client. Anyone else with
-- no invitation is an orphan client whom the frontend routes to the
-- "not invited" welcome page.
-- Safe to re-run.
-- ================================================================

create or replace function handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  uname text;
  fullname text;
  chosen_role user_role;
  inv invitations%rowtype;
  auth_email text;
begin
  auth_email := lower(coalesce(new.email, ''));

  uname := coalesce(new.raw_user_meta_data->>'username',
                    split_part(new.email,'@',1) || '.' || substr(new.id::text,1,4));
  fullname := coalesce(new.raw_user_meta_data->>'full_name',
                       new.raw_user_meta_data->>'name',
                       split_part(new.email,'@',1));

  chosen_role := case new.raw_user_meta_data->>'signup_role'
    when 'studio_owner' then 'studio_owner'::user_role
    when 'client' then 'client'::user_role
    else null
  end;

  if chosen_role is null then
    select * into inv from invitations
     where lower(email) = auth_email
       and status = 'pending'
       and expires_at > now()
     order by created_at desc
     limit 1;
    chosen_role := 'client'::user_role;
  end if;

  insert into profiles (id, username, full_name, email, avatar_url, role, phone, city)
  values (new.id, uname, fullname, new.email,
          new.raw_user_meta_data->>'avatar_url', chosen_role,
          new.raw_user_meta_data->>'phone',
          new.raw_user_meta_data->>'city')
  on conflict (id) do nothing;

  if inv.id is not null then
    if inv.project_id is not null then
      insert into project_members (project_id, user_id, role)
      values (inv.project_id, new.id, case inv.role
        when 'client' then 'client'::project_member_role
        when 'viewer' then 'viewer'::project_member_role
        when 'contributor' then 'contributor'::project_member_role
        else 'client'::project_member_role
      end)
      on conflict (project_id, user_id) do nothing;
    end if;
    update invitations
       set status = 'accepted',
           accepted_at = now(),
           accepted_by = new.id
     where id = inv.id;
  end if;

  return new;
end $$;

create or replace function my_account_status()
returns table (role text, has_studio boolean, project_count int)
language sql stable security definer set search_path = public as $$
  select
    coalesce((select p.role::text from profiles p where p.id = auth.uid()), 'unknown'),
    exists (select 1 from studios where owner_id = auth.uid())
      or exists (select 1 from studio_members where user_id = auth.uid()),
    (select count(*)::int from project_members where user_id = auth.uid());
$$;
grant execute on function my_account_status() to authenticated;

comment on function handle_new_user is 'Create profile on signup. Signup form sets signup_role. If a pending invitation matches the email, auto-accept it (client of that firm).';
comment on function my_account_status is 'Return role + has_studio + project_count for the caller. Used by frontend to decide whether to show the "not invited" screen.';
