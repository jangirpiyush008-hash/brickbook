-- ================================================================
-- BricBook migration 003: practice profile fields + BRIC-ID + awards
-- Safe to re-run.
-- ================================================================

-- 1. Practice visibility enum
do $$ begin
  create type practice_visibility as enum ('public','unlisted','private');
exception when duplicate_object then null; end $$;

-- 2. BRIC-ID sequence (6-digit padded, starts at 1)
create sequence if not exists bric_id_seq minvalue 1 start with 1 no cycle;

-- 3. Extend studios with practice-profile fields
alter table studios
  add column if not exists bric_id text unique,
  add column if not exists tagline text,
  add column if not exists description_long text,
  add column if not exists founded_year int,
  add column if not exists country text default 'India',
  add column if not exists state text,
  add column if not exists website text,
  add column if not exists contact_email text,
  add column if not exists contact_phone text,
  add column if not exists linkedin text,
  add column if not exists instagram text,
  add column if not exists behance text,
  add column if not exists intro_video_url text,
  add column if not exists visibility practice_visibility not null default 'unlisted',
  add column if not exists services text[] not null default '{}',
  add column if not exists profile_completion int not null default 0,
  add column if not exists practice_type text;

create index if not exists studios_visibility_idx on studios(visibility);
create index if not exists studios_bric_id_idx on studios(bric_id);

-- 4. Auto-assign BRIC-ID on insert
create or replace function set_bric_id()
returns trigger language plpgsql as $$
begin
  if NEW.bric_id is null then
    NEW.bric_id := 'BRIC-' || lpad(nextval('bric_id_seq')::text, 6, '0');
  end if;
  return NEW;
end $$;

drop trigger if exists tr_set_bric_id on studios;
create trigger tr_set_bric_id
before insert on studios
for each row execute function set_bric_id();

-- 5. Backfill BRIC-IDs for existing rows
update studios
   set bric_id = 'BRIC-' || lpad(nextval('bric_id_seq')::text, 6, '0')
 where bric_id is null;

-- 6. Awards table
create table if not exists awards (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references studios(id) on delete cascade,
  name text not null,
  organization text,
  year int,
  project_id uuid references projects(id) on delete set null,
  description text,
  url text,
  image_url text,
  featured boolean default false,
  sort_order int default 0,
  created_at timestamptz default now()
);
create index if not exists awards_studio_idx on awards(studio_id);

alter table awards enable row level security;

drop policy if exists awards_read on awards;
drop policy if exists awards_write on awards;

-- Public can read awards for a studio whose visibility is not 'private'
create policy awards_read on awards for select using (
  is_platform_admin()
  or exists (select 1 from studios s where s.id = awards.studio_id and s.visibility <> 'private')
  or is_studio_member(studio_id)
);
create policy awards_write on awards for all using (
  is_platform_admin() or is_studio_member(studio_id)
) with check (
  is_platform_admin() or is_studio_member(studio_id)
);

-- 7. Public-profile RPC: fetch a studio by slug OR bric_id (anonymous-safe)
create or replace function get_practice_public(identifier text)
returns table (
  id uuid, bric_id text, slug text, name text, tagline text,
  city text, state text, country text, founded_year int, practice_type text,
  description_short text, description_long text, logo_url text, cover_url text,
  intro_video_url text, services text[], specialties text[],
  website text, contact_email text, contact_phone text,
  linkedin text, instagram text, behance text,
  verified boolean, visibility practice_visibility,
  fee_rate text, years_experience int
) language sql stable security definer set search_path = public as $$
  select s.id, s.bric_id, s.slug, s.name, s.tagline,
         s.city, s.state, s.country, s.founded_year, s.practice_type,
         s.bio as description_short, s.description_long, s.logo_url, s.cover_url,
         s.intro_video_url, s.services, s.specialties,
         s.website, s.contact_email, s.contact_phone,
         s.linkedin, s.instagram, s.behance,
         s.verified, s.visibility,
         s.fee_rate, s.years_experience
    from studios s
   where (s.slug = identifier or s.bric_id = identifier)
     and s.visibility <> 'private';
$$;
grant execute on function get_practice_public(text) to anon, authenticated;

-- 8. Portfolio projects for the public profile
create or replace function get_practice_projects_public(studio_uuid uuid)
returns table (
  id uuid, code text, name text, city text, area text,
  cover_url text, status project_status, phase project_phase,
  progress int, pinned boolean, started_at date, handover_at date
) language sql stable security definer set search_path = public as $$
  select p.id, p.code, p.name, p.city, p.area,
         p.cover_url, p.status, p.phase,
         p.progress, p.pinned, p.started_at, p.handover_at
    from projects p
   inner join studios s on s.id = p.studio_id
   where p.studio_id = studio_uuid
     and s.visibility <> 'private'
   order by p.pinned desc, p.started_at desc nulls last, p.created_at desc
   limit 50;
$$;
grant execute on function get_practice_projects_public(uuid) to anon, authenticated;

-- 9. Awards for the public profile
create or replace function get_practice_awards_public(studio_uuid uuid)
returns table (
  id uuid, name text, organization text, year int,
  description text, url text, image_url text, featured boolean
) language sql stable security definer set search_path = public as $$
  select a.id, a.name, a.organization, a.year,
         a.description, a.url, a.image_url, a.featured
    from awards a
   inner join studios s on s.id = a.studio_id
   where a.studio_id = studio_uuid
     and s.visibility <> 'private'
   order by a.featured desc, a.year desc nulls last, a.sort_order;
$$;
grant execute on function get_practice_awards_public(uuid) to anon, authenticated;

-- 10. Team members for the public profile (studio_members joined with profiles)
create or replace function get_practice_team_public(studio_uuid uuid)
returns table (
  user_id uuid, full_name text, username text, avatar_url text,
  bio text, city text, team_role team_role, joined_at timestamptz
) language sql stable security definer set search_path = public as $$
  select p.id, p.full_name, p.username, p.avatar_url,
         p.bio, p.city, sm.team_role, sm.joined_at
    from studio_members sm
    inner join profiles p on p.id = sm.user_id
    inner join studios s on s.id = sm.studio_id
   where sm.studio_id = studio_uuid
     and s.visibility <> 'private'
   order by
     case sm.team_role when 'firm_admin' then 1 when 'project_manager' then 2
                       when 'designer' then 3 when 'viewer' then 4 end,
     sm.joined_at;
$$;
grant execute on function get_practice_team_public(uuid) to anon, authenticated;

-- 11. Studio-side helper: fetch the caller's own studio (or null)
create or replace function my_studio()
returns studios language sql stable security definer set search_path = public as $$
  select s.* from studios s
   where s.owner_id = auth.uid()
      or exists (select 1 from studio_members m where m.studio_id = s.id and m.user_id = auth.uid())
   order by (s.owner_id = auth.uid()) desc
   limit 1;
$$;
grant execute on function my_studio() to authenticated;

-- 12. Compute + persist profile_completion (0-100)
create or replace function recalc_profile_completion(sid uuid default null)
returns int language plpgsql security definer set search_path = public as $$
declare
  sid_v uuid;
  s studios%rowtype;
  score int := 0;
begin
  sid_v := coalesce(sid, (select id from studios where owner_id = auth.uid() limit 1));
  if sid_v is null then return 0; end if;
  select * into s from studios where id = sid_v;
  if not found then return 0; end if;

  if s.name       is not null and length(s.name) > 1  then score := score + 8; end if;
  if s.tagline    is not null and length(s.tagline) > 0 then score := score + 6; end if;
  if s.bio        is not null and length(s.bio) > 40 then score := score + 8; end if;
  if s.description_long is not null and length(s.description_long) > 80 then score := score + 8; end if;
  if s.city       is not null then score := score + 4; end if;
  if s.state      is not null then score := score + 3; end if;
  if s.country    is not null then score := score + 2; end if;
  if s.founded_year is not null then score := score + 4; end if;
  if s.logo_url   is not null then score := score + 8; end if;
  if s.cover_url  is not null then score := score + 6; end if;
  if s.website    is not null then score := score + 5; end if;
  if s.contact_email is not null then score := score + 5; end if;
  if s.contact_phone is not null then score := score + 3; end if;
  if s.linkedin   is not null then score := score + 3; end if;
  if s.instagram  is not null then score := score + 3; end if;
  if array_length(s.services, 1) is not null and array_length(s.services, 1) >= 1 then score := score + 6; end if;
  if array_length(s.specialties, 1) is not null and array_length(s.specialties, 1) >= 1 then score := score + 4; end if;
  if exists (select 1 from projects where studio_id = sid_v) then score := score + 8; end if;
  if exists (select 1 from projects where studio_id = sid_v and pinned = true) then score := score + 4; end if;
  if exists (select 1 from awards where studio_id = sid_v) then score := score + 2; end if;

  score := least(100, greatest(0, score));
  update studios set profile_completion = score where id = sid_v;
  return score;
end $$;
grant execute on function recalc_profile_completion(uuid) to authenticated;

-- 13. Comments
comment on function get_practice_public is 'Public read of a practice by slug or BRIC-ID. Enforces visibility<>''private''. Safe to call anonymously.';
comment on function get_practice_projects_public is 'Public list of a practice''s projects (pinned first, then newest).';
comment on function get_practice_awards_public is 'Public list of a practice''s awards.';
comment on function get_practice_team_public is 'Public team-member list joined with profile info.';
comment on function my_studio is 'Convenience: return the caller''s primary studio (owned or member) or NULL.';
comment on function recalc_profile_completion is 'Recalculate the practice profile completion percent (0-100) and persist it.';
