-- =====================================================================
-- TRAINKRUB update (round 16): pop-up notifications on phones.
-- For a database that already ran 01_install.sql and 02_lockdown.sql (and the updates 03, 04 and 05).
-- Safe to run more than once. It changes nothing the website uses today; the pop-ups start working once
-- the "push-send" function is added in Supabase (Edge Functions) and the new website version is live.
--  * keeps which devices turned the pop-ups on, a secret made right here, and the keys the function makes
--  * every new in-app notification makes the database call the "push-send" function (a notification is
--    always saved, even if the call cannot be made)
-- =====================================================================
-- =====================================================================
-- pop-up notifications on phones (Web Push)
-- The database keeps who turned alerts on (which device), a secret, and the keys that prove the
-- messages come from this site. Every new in-app notification makes the database call the
-- "push-send" function, which sends the pop-up. Nothing here can stop a notification from being saved.
-- =====================================================================
do $$ begin
  begin execute 'create extension if not exists pg_net'; exception when others then raise notice 'pg_net could not be enabled here: %', sqlerrm; end;
end $$;

create table if not exists app_private.push_config (
  k          text primary key,
  v          text not null,
  updated_at timestamptz not null default now()
);
-- one device (browser) that wants pop-ups for one person
create table if not exists app_private.push_subs (
  id         bigserial primary key,
  user_id    text not null,
  endpoint   text not null unique,
  p256dh     text not null,
  auth       text not null,
  ua         text,
  created_at timestamptz not null default now(),
  seen_at    timestamptz not null default now()
);
create index if not exists push_subs_user_idx on app_private.push_subs (user_id);
-- what every send did (kept short): select * from app_private.push_log order by id desc limit 20;
create table if not exists app_private.push_log (
  id        bigserial primary key,
  at        timestamptz not null default now(),
  notif_key text,
  sent      int,
  dead      int,
  failed    int,
  detail    text
);
alter table app_private.push_config enable row level security;
alter table app_private.push_subs   enable row level security;
alter table app_private.push_log    enable row level security;

-- the secret that only the database and the push-send function know (made here, never written in any file)
insert into app_private.push_config(k, v) values ('secret', app_private.rand_hex(24)) on conflict (k) do nothing;
insert into app_private.push_config(k, v) values ('fn_url', 'https://eauzvihirpfcjkwyqgel.supabase.co/functions/v1/push-send') on conflict (k) do nothing;

create or replace function app_private.push_secret_ok(p text) returns boolean
language sql stable security definer set search_path = pg_catalog, public, app_private, extensions as $$
  select coalesce(p, '') <> '' and p = (select pc.v from app_private.push_config pc where pc.k = 'secret')
$$;

-- asks the push-send function to do something; never raises (returns false when it could not be asked)
create or replace function app_private.push_fire(p_body jsonb) returns boolean
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare s text; u text;
begin
  select pc.v into s from app_private.push_config pc where pc.k = 'secret';
  select pc.v into u from app_private.push_config pc where pc.k = 'fn_url';
  if s is null or u is null then return false; end if;
  begin
    perform net.http_post(u, p_body, '{}'::jsonb, jsonb_build_object('Content-Type', 'application/json', 'x-push-secret', s), 8000);
    return true;
  exception when others then
    return false;
  end;
end $$;

-- a new notification row -> pop-up (only when that person has at least one device turned on)
create or replace function app_private.push_on_notif() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
begin
  begin
    if exists (select 1 from app_private.push_subs ps where ps.user_id = new.value->>'userId') then
      perform app_private.push_fire(jsonb_build_object('cmd', 'notif', 'key', new.key));
    end if;
  exception when others then
    null;   -- a pop-up problem must never stop the notification itself from being saved
  end;
  return new;
end $$;

drop trigger if exists kv_store_push_notif on public.kv_store;
create trigger kv_store_push_notif after insert on public.kv_store
  for each row when (new.key like 'notif:%') execute function app_private.push_on_notif();

-- ---------------------------------------------------------------------
-- doors for the website (signed-in people)
-- ---------------------------------------------------------------------
-- the public key the browser needs to subscribe (null until the push-send function has made the keys)
create or replace function public.app_push_config(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); pub text;
begin
  select pc.v into pub from app_private.push_config pc where pc.k = 'vapid_pub';
  return jsonb_build_object('publicKey', pub);
end $$;

-- when the keys do not exist yet, ask the function to make them (limited to 3 times in 5 minutes for everybody)
create or replace function public.app_push_wake(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); has boolean;
begin
  select exists (select 1 from app_private.push_config pc where pc.k = 'vapid_pub') into has;
  if has then return jsonb_build_object('ok', true, 'ready', true); end if;
  perform app_private.rate_hit('pwake', 300, 3);
  return jsonb_build_object('ok', true, 'ready', false, 'asked', app_private.push_fire(jsonb_build_object('cmd', 'init')));
end $$;

create or replace function public.app_push_subscribe(p_token text, p_sub jsonb, p_ua text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); ep text; kk text; au text; host text;
begin
  if p_sub is null or jsonb_typeof(p_sub) <> 'object' then perform app_private.err(400, 'invalid'); end if;
  ep := p_sub->>'endpoint'; kk := p_sub->'keys'->>'p256dh'; au := p_sub->'keys'->>'auth';
  if ep is null or length(ep) > 700 or ep !~ '^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?/[^[:space:]]+$' then perform app_private.err(400, 'invalid'); end if;
  -- only the real push servers of the browser makers (the function posts to this address)
  host := lower((regexp_match(ep, '^https://([^/:]+)'))[1]);
  if host !~ '(^|\.)(googleapis\.com|push\.services\.mozilla\.com|push\.apple\.com|notify\.windows\.com)$' then perform app_private.err(400, 'invalid'); end if;
  if kk is null or kk !~ '^[A-Za-z0-9_-]{80,90}$' or au is null or au !~ '^[A-Za-z0-9_-]{20,26}$' then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('ps:' || c.ukey, 3600, 60);
  insert into app_private.push_subs(user_id, endpoint, p256dh, auth, ua) values (c.uid, ep, kk, au, left(app_private.clean_text(p_ua, 120), 120))
  on conflict (endpoint) do update set user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, ua = excluded.ua, seen_at = now();
  -- at most 8 devices per person: the longest-unseen ones go
  delete from app_private.push_subs where id in (
    select ps.id from app_private.push_subs ps where ps.user_id = c.uid order by ps.seen_at desc, ps.id desc offset 8);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.app_push_unsubscribe(p_token text, p_endpoint text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token);
begin
  if p_endpoint is null or length(p_endpoint) > 700 then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('pu:' || c.ukey, 3600, 120);
  delete from app_private.push_subs where endpoint = p_endpoint and user_id = c.uid;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- doors for the push-send function (all need the secret)
-- ---------------------------------------------------------------------
create or replace function public.app_push_take(p_secret text, p_key text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare pub text; priv text; nv jsonb; subs jsonb := '[]'::jsonb;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('ptake', 60, 3000);
  select pc.v into pub  from app_private.push_config pc where pc.k = 'vapid_pub';
  select pc.v into priv from app_private.push_config pc where pc.k = 'vapid_priv';
  if p_key is not null and p_key like 'notif:%' then
    select value into nv from public.kv_store where key = p_key;
    if nv is not null then
      select coalesce(jsonb_agg(jsonb_build_object('endpoint', ps.endpoint, 'p256dh', ps.p256dh, 'auth', ps.auth)), '[]'::jsonb)
        into subs from app_private.push_subs ps where ps.user_id = nv->>'userId';
    end if;
  end if;
  return jsonb_build_object(
    'vapid', case when pub is null or priv is null then null else jsonb_build_object('pub', pub, 'priv', priv) end,
    'subs', subs, 'title', nv->>'title', 'body', nv->>'message', 'tag', case when p_key is null then null else substr(p_key, 7) end);
end $$;

-- keeps the first pair of keys that is stored; later calls just get that pair's public half back
create or replace function public.app_push_vapid_set(p_secret text, p_pub text, p_priv text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare cur text;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  if p_pub is null or p_pub !~ '^[A-Za-z0-9_-]{86,90}$' or p_priv is null or length(p_priv) > 600 or p_priv !~ '^\{.*\}$' then perform app_private.err(400, 'invalid'); end if;
  insert into app_private.push_config(k, v) values ('vapid_priv', p_priv) on conflict (k) do nothing;
  insert into app_private.push_config(k, v) values ('vapid_pub', p_pub) on conflict (k) do nothing;
  select pc.v into cur from app_private.push_config pc where pc.k = 'vapid_pub';
  return jsonb_build_object('pub', cur);
end $$;

create or replace function public.app_push_done(p_secret text, p_key text, p_sent int, p_failed int, p_dead jsonb, p_detail text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare n int := 0;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  if p_dead is not null and jsonb_typeof(p_dead) = 'array' then
    delete from app_private.push_subs where endpoint in (select jsonb_array_elements_text(p_dead));
    get diagnostics n = row_count;
  end if;
  insert into app_private.push_log(notif_key, sent, dead, failed, detail) values (left(p_key, 90), p_sent, n, p_failed, left(p_detail, 300));
  delete from app_private.push_log where id in (select pl.id from app_private.push_log pl order by pl.id desc offset 300);
  return jsonb_build_object('ok', true, 'removed', n);
end $$;

-- =====================================================================
-- who may call what (re-applied so every function keeps the same rules)
-- =====================================================================
do $$
declare f record;
begin
  -- nothing is callable by default ...
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname in ('app_private') or (n.nspname = 'public' and p.proname like 'app\_%') loop
    execute format('revoke all on function %s from public, anon, authenticated', f.sig);
  end loop;
  -- ... except these doors
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname in (
              'app_login','app_whoami','app_logout','app_logout_all','app_register_customer','app_apply_trainer','app_apply_cert',
              'app_approve_trainer','app_reject_trainer','app_change_password','app_reset_password',
              'app_google_login','app_google_link','app_google_unlink','app_get','app_list','app_set','app_del',
              'app_find_trainer','app_admin_maintain','app_admin_stats','app_ping','app_finish_apply',
              'app_push_config','app_push_wake','app_push_subscribe','app_push_unsubscribe','app_push_take','app_push_vapid_set','app_push_done') loop
    execute format('grant execute on function %s to anon, authenticated', f.sig);
  end loop;
end $$;

-- ask the function to make its keys now (works only if the function is already added; otherwise the website asks again later)
do $$ begin
  if not exists (select 1 from app_private.push_config pc where pc.k = 'vapid_pub') then
    perform app_private.push_fire('{"cmd":"init"}'::jsonb);
  end if;
exception when others then null;
end $$;

-- make the API pick up the changes straight away
notify pgrst, 'reload schema';

-- result: every line should say ok (the last one says "waiting" until the push-send function is added)
select 'pg_net (sends the pop-ups)' as item,
       case when exists (select 1 from pg_extension where extname = 'pg_net') then 'ok' else 'OFF - open Database > Extensions and turn on pg_net, then run this again' end as result
union all
select 'trigger on new notifications', case when exists (select 1 from pg_trigger where tgname = 'kv_store_push_notif') then 'ok' else 'MISSING' end
union all
select 'secret', case when exists (select 1 from app_private.push_config pc where pc.k = 'secret') then 'ok' else 'MISSING' end
union all
select 'doors for the website', case when (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'public' and p.proname like 'app\_push\_%') = 7 then 'ok' else 'MISSING' end
union all
select 'push-send function keys', case when exists (select 1 from app_private.push_config pc where pc.k = 'vapid_pub') then 'ok' else 'waiting for the push-send function' end;
