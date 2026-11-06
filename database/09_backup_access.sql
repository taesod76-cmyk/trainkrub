-- =====================================================================
-- TRAINKUB update (round 19): a read-only login for the nightly backup.
-- Run it in Supabase > SQL Editor. Safe to run more than once: running it again makes a NEW password (the old one stops working).
--  * creates the login "backup_ro". It can only READ five tables (the app data, the password hashes, the push settings,
--    the push devices and the security log). It cannot write, cannot change anything and cannot call any function.
--  * closes a small gap: functions made by the earlier update scripts were left callable by "everyone" inside the private
--    schema (nobody could reach them from the app, but the backup login could). They are closed now.
--  * the result shows a one-time password. Copy it straight into GitHub (the person doing the setup is told where).
-- =====================================================================
do $$
declare
  pw text := replace(gen_random_uuid()::text || gen_random_uuid()::text, '-', '');
  t text;
begin
  if not exists (select 1 from pg_roles where rolname = 'backup_ro') then
    create role backup_ro login nosuperuser nocreatedb nocreaterole noinherit connection limit 3;
  end if;
  execute format('alter role backup_ro with login password %L', pw);
  alter role backup_ro set default_transaction_read_only = on;
  alter role backup_ro set statement_timeout = '600s';

  -- nothing in the private schema is callable by everyone (the same rule as part 6 of the install script)
  revoke all on all functions in schema app_private from public;

  grant usage on schema public to backup_ro;
  grant usage on schema app_private to backup_ro;
  foreach t in array array['public.kv_store', 'app_private.cred', 'app_private.push_config', 'app_private.push_subs', 'app_private.audit'] loop
    execute format('grant select on %s to backup_ro', t);
    execute format('drop policy if exists backup_ro_read on %s', t);
    execute format('create policy backup_ro_read on %s for select to backup_ro using (true)', t);
  end loop;
  perform set_config('tk.backup_pw', pw, false);
end $$;

notify pgrst, 'reload schema';

-- result: the first line should say ok; the second is the password (shown once); the third must be 0
select 'backup login' as item, case when exists (select 1 from pg_roles where rolname = 'backup_ro' and rolcanlogin) then 'ok' else 'MISSING' end as result
union all
select 'password (copy it now)', coalesce(current_setting('tk.backup_pw', true), '(not shown: run this script again)')
union all
select 'private functions open to everyone', (select count(*)::text from pg_proc p join pg_namespace n on n.oid = p.pronamespace
        where n.nspname = 'app_private' and has_function_privilege('public', p.oid, 'execute'));
