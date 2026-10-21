-- MUSH ROOM: 관리자 기능 (회원 가입 승인 · 브랜드 입점 신청 · 문의/컴플레인)
-- saved_looks.sql 을 먼저 실행한 뒤, Supabase 대시보드 → SQL Editor 에 붙여넣고 Run (한 번만)
-- 맨 아래 "관리자 지정" 줄의 이메일 계정이 관리자가 됨 (사이트에 먼저 가입해 둬야 함)

-- ─────────────────────────────────────────────
-- 1) profiles: 회원 상태 (가입 승인 · 관리자 여부)
-- ─────────────────────────────────────────────
create table if not exists public.profiles (
  id          uuid primary key references auth.users (id) on delete cascade,
  email       text not null,
  name        text,
  role        text not null default 'user'    check (role in ('user', 'admin')),
  status      text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at  timestamptz not null default now(),
  approved_at timestamptz
);

-- 새로 가입하면 profiles 에 '승인 대기' 로 자동 등록
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'name', split_part(new.email, '@', 1)))
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- 이미 가입해 있던 회원은 그대로 쓸 수 있게 '승인' 으로 등록
insert into public.profiles (id, email, name, status, approved_at)
select id, email, coalesce(raw_user_meta_data ->> 'name', split_part(email, '@', 1)), 'approved', now()
from auth.users
on conflict (id) do nothing;

-- 정책에서 쓰는 도우미 함수 (security definer: profiles 정책이 자기 자신을 다시 부르지 않게)
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

create or replace function public.is_approved()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and status = 'approved');
$$;

alter table public.profiles enable row level security;

drop policy if exists "profiles select own or admin" on public.profiles;
create policy "profiles select own or admin" on public.profiles
  for select to authenticated using ((select auth.uid()) = id or public.is_admin());

-- 상태·권한 변경은 관리자만 (본인이 직접 승인하거나 관리자가 될 수 없음)
drop policy if exists "profiles update admin" on public.profiles;
create policy "profiles update admin" on public.profiles
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- ─────────────────────────────────────────────
-- 2) brand_applications: 브랜드 입점 신청
-- ─────────────────────────────────────────────
create table if not exists public.brand_applications (
  id           bigint generated always as identity primary key,
  user_id      uuid default auth.uid() references auth.users (id) on delete set null,
  brand_name   text not null,
  contact_name text not null,
  email        text not null,
  instagram    text,
  website      text,
  category     text,
  message      text not null,
  status       text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  admin_note   text,
  created_at   timestamptz not null default now(),
  reviewed_at  timestamptz
);
create index if not exists brand_applications_status_idx on public.brand_applications (status);

alter table public.brand_applications enable row level security;

-- 누구나(비로그인 포함) 신청 가능, 단 처음 상태는 무조건 '대기'
drop policy if exists "brand apply insert" on public.brand_applications;
create policy "brand apply insert" on public.brand_applications
  for insert to anon, authenticated
  with check (status = 'pending' and admin_note is null and reviewed_at is null
              and (user_id is null or user_id = (select auth.uid())));

drop policy if exists "brand apply select own or admin" on public.brand_applications;
create policy "brand apply select own or admin" on public.brand_applications
  for select to authenticated using (user_id = (select auth.uid()) or public.is_admin());

drop policy if exists "brand apply update admin" on public.brand_applications;
create policy "brand apply update admin" on public.brand_applications
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- ─────────────────────────────────────────────
-- 3) complaints: 문의 · 컴플레인
-- ─────────────────────────────────────────────
create table if not exists public.complaints (
  id          bigint generated always as identity primary key,
  user_id     uuid default auth.uid() references auth.users (id) on delete set null,
  email       text not null,
  category    text not null default '기타',
  subject     text not null,
  message     text not null,
  status      text not null default 'open' check (status in ('open', 'in_progress', 'resolved')),
  admin_reply text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz
);
create index if not exists complaints_status_idx on public.complaints (status);

alter table public.complaints enable row level security;

drop policy if exists "complaints insert" on public.complaints;
create policy "complaints insert" on public.complaints
  for insert to anon, authenticated
  with check (status = 'open' and admin_reply is null
              and (user_id is null or user_id = (select auth.uid())));

drop policy if exists "complaints select own or admin" on public.complaints;
create policy "complaints select own or admin" on public.complaints
  for select to authenticated using (user_id = (select auth.uid()) or public.is_admin());

drop policy if exists "complaints update admin" on public.complaints;
create policy "complaints update admin" on public.complaints
  for update to authenticated using (public.is_admin()) with check (public.is_admin());

-- ─────────────────────────────────────────────
-- 4) saved_looks: 승인된 회원만 계정 저장 + 관리자는 통계용으로 조회
-- ─────────────────────────────────────────────
drop policy if exists "saved_looks insert own" on public.saved_looks;
create policy "saved_looks insert own" on public.saved_looks
  for insert to authenticated with check ((select auth.uid()) = user_id and public.is_approved());

drop policy if exists "saved_looks select admin" on public.saved_looks;
create policy "saved_looks select admin" on public.saved_looks
  for select to authenticated using (public.is_admin());

grant select, update on public.profiles to authenticated;
grant insert on public.brand_applications, public.complaints to anon, authenticated;
grant select, update on public.brand_applications, public.complaints to authenticated;

-- ─────────────────────────────────────────────
-- 5) 관리자 지정: 아래 이메일 계정을 관리자로 (사이트에서 먼저 회원가입해 둬야 함)
-- ─────────────────────────────────────────────
update public.profiles set role = 'admin', status = 'approved', approved_at = now()
where email = 'lsyio1234@gmail.com';
