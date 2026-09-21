-- Run this once in your Supabase project: Dashboard → SQL Editor → New query
-- This creates the single key/value table TRAINKRUB uses for all its data
-- (trainers, customers, bookings, packages, notifications, etc).

create table if not exists kv_store (
  key text primary key,
  value jsonb not null,
  updated_at timestamptz not null default now()
);

-- Row Level Security must be ON for the anon (public) key to work at all,
-- but the policies below leave it fully open: anyone with your anon key
-- can read AND write every row. That matches how this app already works
-- (its login system is enforced only in the browser, not the database),
-- so it's fine for a demo/prototype. Do not put real secrets or payment
-- data in this table as-is — for production, replace these four "true"
-- policies with rules based on Supabase Auth (auth.uid()) instead.
alter table kv_store enable row level security;

drop policy if exists "public read" on kv_store;
create policy "public read" on kv_store for select using (true);

drop policy if exists "public insert" on kv_store;
create policy "public insert" on kv_store for insert with check (true);

drop policy if exists "public update" on kv_store;
create policy "public update" on kv_store for update using (true);

drop policy if exists "public delete" on kv_store;
create policy "public delete" on kv_store for delete using (true);

-- Speeds up the prefix search the app does for every "list" query
-- (e.g. all bookings, all trainers) via `like 'prefix%'`.
create index if not exists kv_store_key_prefix_idx on kv_store (key text_pattern_ops);
