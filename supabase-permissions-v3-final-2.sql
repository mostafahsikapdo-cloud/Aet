-- Nabra CHAT / Permissions migration v1
-- Apply AFTER the existing supabase-schema.sql has succeeded.
-- Safe to re-run.

create extension if not exists pgcrypto;

-- 1) Roles: super_admin > admin > moderator > member
alter table public.profiles
  drop constraint if exists profiles_role_check;
alter table public.profiles
  add constraint profiles_role_check
  check (role in ('member', 'moderator', 'admin', 'super_admin'));

-- 2) Room membership / moderation scope
create table if not exists public.room_members (
  room_id uuid not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  is_muted boolean not null default false,
  primary key (room_id, user_id)
);
create index if not exists room_members_user_idx on public.room_members(user_id, joined_at desc);

-- Ensure the public default room exists so normal members never need room-creation privileges.
insert into public.rooms (name, description, is_open)
select 'المجلس', 'الغرفة العامة لنَبرة CHAT', true
where not exists (select 1 from public.rooms where name = 'المجلس');

-- 3) Notifications / announcements / audit log
create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  recipient_id uuid references public.profiles(id) on delete cascade,
  kind text not null check (kind in ('welcome', 'daily', 'announcement')),
  title text not null,
  body text not null check (char_length(trim(body)) between 1 and 4000),
  scheduled_at timestamptz,
  sent_at timestamptz,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists notifications_recipient_idx on public.notifications(recipient_id, created_at desc);
create index if not exists notifications_schedule_idx on public.notifications(scheduled_at) where sent_at is null;

create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text not null check (char_length(trim(body)) between 1 and 4000),
  scheduled_at timestamptz,
  published_at timestamptz,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists announcements_schedule_idx on public.announcements(scheduled_at) where published_at is null;

create table if not exists public.admin_logs (
  id uuid primary key default gen_random_uuid(),
  performed_by uuid references public.profiles(id) on delete set null,
  action text not null,
  target_type text,
  target_id uuid,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists admin_logs_created_idx on public.admin_logs(created_at desc);
create index if not exists admin_logs_actor_idx on public.admin_logs(performed_by, created_at desc);

-- 4) Helper: role of the authenticated user. SECURITY DEFINER avoids RLS recursion.
create or replace function public.current_profile_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid();
$$;

revoke all on function public.current_profile_role() from public;
grant execute on function public.current_profile_role() to authenticated;

create or replace function public.has_any_role(required_roles text[])
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select coalesce(public.current_profile_role() = any(required_roles), false);
$$;

revoke all on function public.has_any_role(text[]) from public;
grant execute on function public.has_any_role(text[]) to authenticated;

-- 5) Prevent privilege escalation through direct profile inserts/updates.
create or replace function public.protect_profile_role()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  actor_role text;
begin
  if tg_op = 'INSERT' then
    if new.role <> 'member' and public.current_profile_role() <> 'super_admin' then
      raise exception 'لا يمكن إنشاء حساب بصلاحية إدارية';
    end if;
  elsif new.role is distinct from old.role then
    actor_role := public.current_profile_role();
    if actor_role = 'super_admin' then
      null;
    elsif actor_role = 'admin' and new.role in ('member', 'moderator') then
      null;
    else
      raise exception 'ليس لديك صلاحية لتغيير رتبة المستخدم';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists protect_profile_role_trigger on public.profiles;
create trigger protect_profile_role_trigger
before insert or update on public.profiles
for each row execute function public.protect_profile_role();

-- 6) Profiles policies
alter table public.profiles enable row level security;
drop policy if exists "users update own profile" on public.profiles;
drop policy if exists "admins update profiles" on public.profiles;
create policy "users update own profile" on public.profiles
for update to authenticated
using (auth.uid() = id)
with check (auth.uid() = id);
create policy "admins update profiles" on public.profiles
for update to authenticated
using (public.has_any_role(array['admin','super_admin']))
with check (public.has_any_role(array['admin','super_admin']));

-- 7) Rooms: public read, creation/change restricted to management.
drop policy if exists "authenticated users create rooms" on public.rooms;
drop policy if exists "management create rooms" on public.rooms;
drop policy if exists "management update rooms" on public.rooms;
drop policy if exists "management delete rooms" on public.rooms;
create policy "management create rooms" on public.rooms
for insert to authenticated
with check (public.has_any_role(array['admin','super_admin']));
create policy "management update rooms" on public.rooms
for update to authenticated
using (public.has_any_role(array['admin','super_admin']))
with check (public.has_any_role(array['admin','super_admin']));
create policy "management delete rooms" on public.rooms
for delete to authenticated
using (public.has_any_role(array['admin','super_admin']));

-- 8) Room membership
alter table public.room_members enable row level security;
drop policy if exists "members read own room memberships" on public.room_members;
drop policy if exists "management read room memberships" on public.room_members;
drop policy if exists "users join open rooms" on public.room_members;
drop policy if exists "management manage room memberships" on public.room_members;
create policy "members read own room memberships" on public.room_members
for select to authenticated
using (auth.uid() = user_id);
create policy "management read room memberships" on public.room_members
for select to authenticated
using (public.has_any_role(array['admin','super_admin']) or exists (
  select 1 from public.rooms r
  where r.id = room_members.room_id and r.moderator_id = auth.uid()
));
create policy "users join open rooms" on public.room_members
for insert to authenticated
with check (
  auth.uid() = user_id and exists (
    select 1 from public.rooms r where r.id = room_members.room_id and r.is_open = true
  )
);
create policy "management manage room memberships" on public.room_members
for all to authenticated
using (public.has_any_role(array['admin','super_admin']) or exists (
  select 1 from public.rooms r where r.id = room_members.room_id and r.moderator_id = auth.uid()
))
with check (public.has_any_role(array['admin','super_admin']) or exists (
  select 1 from public.rooms r where r.id = room_members.room_id and r.moderator_id = auth.uid()
));

-- 9) Messages: members send; moderators manage messages in assigned rooms; management manages all.
drop policy if exists "authenticated users read messages" on public.messages;
drop policy if exists "authenticated users send messages" on public.messages;
drop policy if exists "users delete own messages" on public.messages;
drop policy if exists "room members read messages" on public.messages;
drop policy if exists "room members send messages" on public.messages;
drop policy if exists "moderators manage room messages" on public.messages;
drop policy if exists "management manage messages" on public.messages;
create policy "room members read messages" on public.messages
for select to authenticated
using (
  exists (select 1 from public.room_members rm where rm.room_id = messages.room_id and rm.user_id = auth.uid())
  or public.has_any_role(array['admin','super_admin'])
  or exists (select 1 from public.rooms r where r.id = messages.room_id and r.moderator_id = auth.uid())
);
create policy "room members send messages" on public.messages
for insert to authenticated
with check (
  auth.uid() = user_id
  and exists (select 1 from public.room_members rm where rm.room_id = messages.room_id and rm.user_id = auth.uid() and rm.is_muted = false)
);
create policy "moderators manage room messages" on public.messages
for delete to authenticated
using (
  exists (select 1 from public.rooms r where r.id = messages.room_id and r.moderator_id = auth.uid())
);
create policy "management manage messages" on public.messages
for all to authenticated
using (public.has_any_role(array['admin','super_admin']))
with check (public.has_any_role(array['admin','super_admin']));

-- 10) Notifications and announcements: management only creates; recipients read their own.
alter table public.notifications enable row level security;
drop policy if exists "recipients read notifications" on public.notifications;
drop policy if exists "management manage notifications" on public.notifications;
create policy "recipients read notifications" on public.notifications
for select to authenticated
using (recipient_id = auth.uid() or recipient_id is null);
create policy "management manage notifications" on public.notifications
for all to authenticated
using (public.has_any_role(array['admin','super_admin']))
with check (public.has_any_role(array['admin','super_admin']));

alter table public.announcements enable row level security;
drop policy if exists "published announcements are readable" on public.announcements;
drop policy if exists "management manage announcements" on public.announcements;
create policy "published announcements are readable" on public.announcements
for select to authenticated
using (published_at is not null);
create policy "management manage announcements" on public.announcements
for all to authenticated
using (public.has_any_role(array['admin','super_admin']))
with check (public.has_any_role(array['admin','super_admin']));

-- 11) Audit log: management can write; only super_admin can read all logs.
alter table public.admin_logs enable row level security;
drop policy if exists "management create audit logs" on public.admin_logs;
drop policy if exists "super admins read audit logs" on public.admin_logs;
create policy "management create audit logs" on public.admin_logs
for insert to authenticated
with check (performed_by = auth.uid() and public.has_any_role(array['admin','super_admin']));
create policy "super admins read audit logs" on public.admin_logs
for select to authenticated
using (public.has_any_role(array['super_admin']));

-- 12) Realtime (idempotent)
do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
end
$$;
