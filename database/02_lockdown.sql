-- =====================================================================
-- TRAINKRUB security step 2: close the old open door.
-- Run this ONLY after the new version of the website is live.
-- =====================================================================
-- accounts made by the old website since step 1 (still holding a plain password) are converted first
insert into app_private.cred(ukey, pw_hash)
select k.key, extensions.crypt(k.value->>'password', extensions.gen_salt('bf', 10))
  from public.kv_store k
 where (k.key like 'trainer:%' or k.key like 'customer:%' or k.key like 'trainerApp:%')
   and coalesce(k.value->>'password','') <> ''
   and not exists (select 1 from app_private.cred c where c.ukey = k.key);
-- no password may stay in the data
update public.kv_store set value = value - 'password' where value ? 'password';
-- the leftovers of the old housekeeping
delete from public.kv_store where key = 'system:lastCleanup';

-- nobody can touch the table directly any more; only the functions can
drop policy if exists "public read"   on public.kv_store;
drop policy if exists "public insert" on public.kv_store;
drop policy if exists "public update" on public.kv_store;
drop policy if exists "public delete" on public.kv_store;
alter table public.kv_store enable row level security;
revoke all on public.kv_store from anon, authenticated;
