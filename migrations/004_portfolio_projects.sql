-- ================================================================
-- BricBook migration 004: portfolio projects
-- Extends projects table so a single row can be a portfolio piece
-- (public on the practice profile) or a construction project (private,
-- with client_id + workspace).
-- Safe to re-run.
-- ================================================================

-- 1. Enums
do $$ begin
  create type project_kind as enum ('construction','portfolio');
exception when duplicate_object then null; end $$;

do $$ begin
  create type portfolio_status as enum ('completed','ongoing','concept','competition','proposed');
exception when duplicate_object then null; end $$;

-- 2. Extend projects with portfolio fields
alter table projects
  add column if not exists kind project_kind not null default 'construction',
  add column if not exists year int,
  add column if not exists project_type text,
  add column if not exists description text,
  add column if not exists description_long text,
  add column if not exists gallery_urls text[] not null default '{}',
  add column if not exists video_url text,
  add column if not exists portfolio_status portfolio_status,
  add column if not exists featured boolean not null default false,
  add column if not exists sort_order int not null default 0,
  add column if not exists external_url text,
  add column if not exists team_credits text;

create index if not exists projects_kind_idx on projects(kind);
create index if not exists projects_studio_kind_idx on projects(studio_id, kind);

-- 3. Public storage bucket for practice project media
insert into storage.buckets (id, name, public)
values ('practice', 'practice', true)
on conflict (id) do update set public = excluded.public;

-- 4. Storage policies for the practice bucket
--    Path convention: <studio_id>/<project_id>/<filename>
--    Authenticated users can upload / delete files scoped to their studio;
--    everyone can read (bucket is public).
drop policy if exists "practice_upload" on storage.objects;
drop policy if exists "practice_read" on storage.objects;
drop policy if exists "practice_update" on storage.objects;
drop policy if exists "practice_delete" on storage.objects;

create policy "practice_read" on storage.objects for select to public
  using (bucket_id = 'practice');

create policy "practice_upload" on storage.objects for insert to authenticated
  with check (
    bucket_id = 'practice'
    and (
      is_platform_admin()
      or is_studio_member((split_part(name, '/', 1))::uuid)
    )
  );

create policy "practice_update" on storage.objects for update to authenticated
  using (
    bucket_id = 'practice'
    and (is_platform_admin() or is_studio_member((split_part(name, '/', 1))::uuid))
  );

create policy "practice_delete" on storage.objects for delete to authenticated
  using (
    bucket_id = 'practice'
    and (is_platform_admin() or is_studio_member((split_part(name, '/', 1))::uuid))
  );

-- 5. Add a public read policy for portfolio projects
--    (existing projects_select is is_project_member; that's fine for construction
--     but blocks the marketplace / practice profile from showing portfolio work).
drop policy if exists projects_portfolio_public on projects;
create policy projects_portfolio_public on projects for select using (
  kind = 'portfolio'
  and exists (
    select 1 from studios s
    where s.id = projects.studio_id and s.visibility <> 'private'
  )
);

-- 6. Helper: portfolio projects for a studio, ordered for public display
create or replace function get_portfolio_projects(studio_uuid uuid, only_featured boolean default false)
returns setof projects language sql stable security definer set search_path = public as $$
  select p.* from projects p
   inner join studios s on s.id = p.studio_id
   where p.studio_id = studio_uuid
     and p.kind = 'portfolio'
     and s.visibility <> 'private'
     and (not only_featured or p.featured = true)
   order by p.featured desc, p.sort_order, coalesce(p.year, 0) desc, p.created_at desc;
$$;
grant execute on function get_portfolio_projects(uuid, boolean) to anon, authenticated;

-- 7. Ensure code generator handles portfolio projects (auto slug per firm)
create sequence if not exists portfolio_project_seq minvalue 1 start with 1 no cycle;

create or replace function ensure_project_code()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if NEW.code is null or NEW.code = '' then
    if NEW.kind = 'portfolio' then
      NEW.code := 'PORT-' || lpad(nextval('portfolio_project_seq')::text, 6, '0');
    else
      NEW.code := 'SPDL' || lpad(nextval('portfolio_project_seq')::text, 4, '0');
    end if;
  end if;
  return NEW;
end $$;

drop trigger if exists tr_ensure_project_code on projects;
create trigger tr_ensure_project_code
before insert on projects
for each row execute function ensure_project_code();

comment on function get_portfolio_projects is 'Public list of a studio''s portfolio projects (featured first, then order).';
comment on function ensure_project_code is 'Auto-generate a human-readable code for projects that don''t supply one.';
