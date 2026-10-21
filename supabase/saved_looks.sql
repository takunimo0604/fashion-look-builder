-- MUSH ROOM: 저장한 룩(코디) 테이블
-- Supabase 대시보드 → SQL Editor 에 붙여넣고 Run 하면 됨 (한 번만)

create table if not exists public.saved_looks (
  id          bigint generated always as identity primary key,
  user_id     uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title       text not null,
  items       jsonb not null,          -- 착장 아이템 [{ id, category, brand, name, price, image, musinsaUrl }]
  total_price integer not null default 0,
  created_at  timestamptz not null default now()
);

create index if not exists saved_looks_user_id_idx on public.saved_looks (user_id);

-- RLS: 로그인한 본인 행만 보고/쓰고/지울 수 있음 (다른 유저 ID로 넣는 것도 차단)
alter table public.saved_looks enable row level security;

drop policy if exists "saved_looks select own" on public.saved_looks;
create policy "saved_looks select own" on public.saved_looks
  for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "saved_looks insert own" on public.saved_looks;
create policy "saved_looks insert own" on public.saved_looks
  for insert to authenticated with check ((select auth.uid()) = user_id);

drop policy if exists "saved_looks delete own" on public.saved_looks;
create policy "saved_looks delete own" on public.saved_looks
  for delete to authenticated using ((select auth.uid()) = user_id);
