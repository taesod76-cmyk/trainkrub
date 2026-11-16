-- =====================================================================
-- TRAINKUB update (round 22): sign in with LINE, notices as LINE messages, record of accepted terms, delete my account.
-- For a database that already ran 01_install.sql and 02_lockdown.sql (and the updates 03 to 09).
-- Safe to run more than once. Run it BEFORE publishing the website version that goes with it.
--  * keeps which LINE user belongs to which account (the browser never holds a LINE secret and never says who it is by itself)
--  * every new in-app notice also asks the "line" function to send a LINE message (a notice is always saved, even if LINE fails)
--  * a record of which version of the terms each person accepted, and a door for a customer to delete their own account
--  * accounts made with LINE or Google have no password: resetting one by the admin is refused
-- It adds tables and functions only; no stored data is changed.
-- =====================================================================
create or replace function public.app_reset_password(p_token text, p_target text, p_new text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); v jsonb; r text;
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  if p_target is null or p_target !~ '^(customer|trainer):[A-Za-z0-9_]{1,60}$' then perform app_private.err(400, 'invalid'); end if;
  select value into v from public.kv_store where key = p_target;
  if v is null then return jsonb_build_object('ok', false, 'reason', 'gone'); end if;
  if v->>'authProvider' in ('google', 'line') then return jsonb_build_object('ok', false, 'reason', 'google'); end if;
  if not app_private.valid_password(p_new, v->>'phone') then return jsonb_build_object('ok', false, 'reason', 'weak'); end if;
  insert into app_private.cred(ukey, pw_hash) values (p_target, extensions.crypt(p_new, extensions.gen_salt('bf', 10)))
  on conflict (ukey) do update set pw_hash = excluded.pw_hash, updated_at = now();
  delete from app_private.session where ukey = p_target;
  r := split_part(p_target, ':', 1);
  delete from app_private.fail where bucket in ('a:' || r || ':' || lower(coalesce(v->>'username','')), 'a:' || r || ':' || lower(coalesce(v->>'phone','')));
  perform app_private.audit(c.ukey, 'reset_password', p_target, true, null);
  return jsonb_build_object('ok', true);
end $$;

create or replace function app_private.w_customer(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare nm text; ph text; photo text; arr jsonb; x jsonb; h jsonb; hn jsonb; filled boolean; consent boolean; now_s text :=
          to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if o is null then perform app_private.err(403, 'forbidden'); end if;
  if c.role = 'admin' then
    -- the admin's view has no profile picture and no health information, so only the status of what was sent counts; the stored row is kept as it is
    if n->>'status' in ('active','suspended') and app_private.same_except(o, n, array['status','photo','health']) then
      return o || jsonb_build_object('status', n->>'status');
    end if;
    perform app_private.err(403, 'forbidden');
  end if;
  if c.role <> 'customer' or o->>'id' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.same_except(o, n, array['name','phone','username','photo','pinnedTrainerIds','myTrainerIds','health']) then
    perform app_private.err(403, 'forbidden');
  end if;
  -- health information (the person's own, optional): text with limits, and the person's agreement that the trainers they work with may see it
  if n ? 'health' then
    h := n->'health';
    if h is null or jsonb_typeof(h) = 'null' then
      n := n - 'health';
    else
      if jsonb_typeof(h) <> 'object' then perform app_private.err(400, 'invalid'); end if;
      hn := jsonb_build_object(
        'conditions', app_private.clean_text(h->>'conditions', 400), 'injuries', app_private.clean_text(h->>'injuries', 400),
        'meds', app_private.clean_text(h->>'meds', 300), 'goal', app_private.clean_text(h->>'goal', 300),
        'emName', app_private.clean_text(h->>'emName', 60), 'emPhone', app_private.clean_text(h->>'emPhone', 20),
        'age', app_private.clean_text(h->>'age', 3), 'weight', app_private.clean_text(h->>'weight', 6), 'height', app_private.clean_text(h->>'height', 6));
      if hn->>'emPhone' <> '' and not app_private.valid_phone(hn->>'emPhone') then perform app_private.err(400, 'invalid'); end if;
      -- numbers are optional; a wrong one is refused (written with CASE so a bad text is never cast)
      if hn->>'age' <> '' and not (case when hn->>'age' ~ '^[0-9]{1,3}$' then (hn->>'age')::int between 1 and 120 else false end) then perform app_private.err(400, 'invalid'); end if;
      if hn->>'weight' <> '' and not (case when hn->>'weight' ~ '^[0-9]{1,3}(\.[0-9])?$' then (hn->>'weight')::numeric between 10 and 400 else false end) then perform app_private.err(400, 'invalid'); end if;
      if hn->>'height' <> '' and not (case when hn->>'height' ~ '^[0-9]{2,3}(\.[0-9])?$' then (hn->>'height')::numeric between 50 and 260 else false end) then perform app_private.err(400, 'invalid'); end if;
      filled := exists (select 1 from jsonb_each_text(hn) e where e.value <> '');
      consent := coalesce(h->>'consent', '') = 'true';
      if filled and not consent then perform app_private.err(400, 'consent_needed'); end if;
      hn := hn || jsonb_build_object('consent', consent, 'updatedAt', now_s,
              'consentAt', case when not consent then null when coalesce(o->'health'->>'consent', '') = 'true' and o->'health'->>'consentAt' is not null then o->'health'->'consentAt' else to_jsonb(now_s) end);
      n := n || jsonb_build_object('health', jsonb_strip_nulls(hn));
    end if;
  end if;
  nm := app_private.clean_text(n->>'name', 60);
  if nm = '' then perform app_private.err(400, 'invalid'); end if;
  ph := app_private.clean_text(n->>'phone', 20);
  if o->>'authProvider' in ('google', 'line') then
    if ph <> '' and not app_private.valid_phone(ph) then perform app_private.err(400, 'invalid'); end if;
    n := n || jsonb_build_object('username', o->>'username');
  else
    if not app_private.valid_phone(ph) then perform app_private.err(400, 'invalid'); end if;
    n := n || jsonb_build_object('username', ph);
    if ph <> coalesce(o->>'phone','') then
      perform pg_advisory_xact_lock(hashtext('phone:' || ph));
      if exists (select 1 from public.kv_store where key like 'customer:%' and key <> p_key and (value->>'phone' = ph or value->>'username' = ph)) then
        perform app_private.err(409, 'phone_used');
      end if;
    end if;
  end if;
  n := n || jsonb_build_object('name', nm, 'phone', ph);
  if n ? 'photo' then
    photo := n->>'photo';
    if photo is null or not app_private.is_data_url(photo, 64000) then n := n - 'photo'; end if;
  end if;
  foreach x in array array[n->'pinnedTrainerIds', n->'myTrainerIds'] loop
    if x is not null and (jsonb_typeof(x) <> 'array' or jsonb_array_length(x) > 200) then perform app_private.err(400, 'invalid'); end if;
    if x is not null and exists (select 1 from jsonb_array_elements(x) e where jsonb_typeof(e) <> 'string' or length(e #>> '{}') > 60) then
      perform app_private.err(400, 'invalid');
    end if;
  end loop;
  if nm <> coalesce(o->>'name','') then perform app_private.propagate_name('customer', o->>'id', nm); end if;
  return n;
end $$;

-- =====================================================================
-- LINE (sign in inside LINE + messages from the LINE Official Account)
-- The browser never talks to LINE and never holds a LINE secret. Two server functions do (the "line" Edge Function):
--   * it checks the LINE sign-in token the browser gets inside LINE (LIFF) and asks THIS part to sign the person in;
--   * it sends the same notices the app already makes as LINE messages, and tells us who added / blocked the account.
-- Who is who is kept here: which LINE user belongs to which app account. Nothing in this part can stop a notice from being saved.
-- =====================================================================
-- one LINE user <-> one app account (a person can have one customer account and one trainer account)
create table if not exists app_private.line_link (
  line_sub   text not null,                      -- the LINE user id (checked by the function, never typed by a person)
  role       text not null check (role in ('customer', 'trainer')),
  uid        text not null,                      -- the app account id (c_..., cl_..., t_...)
  ukey       text not null,                      -- the key of the account row (customer:... / trainer:...)
  name       text,
  friend     boolean not null default false,     -- true while the person has the Official Account added (not blocked)
  created_at timestamptz not null default now(),
  last_login timestamptz not null default now(),
  primary key (line_sub, role)
);
create unique index if not exists line_link_ukey_idx on app_private.line_link (ukey);
create index if not exists line_link_uid_idx on app_private.line_link (uid);
-- LINE messages sent per month (Bangkok time) so the free plan's limit is never crossed by surprise
create table if not exists app_private.line_usage (
  ym text primary key,
  n  int  not null default 0
);
-- what the line function did (kept short): select * from app_private.line_log order by id desc limit 20;
create table if not exists app_private.line_log (
  id     bigserial primary key,
  at     timestamptz not null default now(),
  kind   text,
  ref    text,
  sent   int,
  failed int,
  detail text
);
alter table app_private.line_link  enable row level security;
alter table app_private.line_usage enable row level security;
alter table app_private.line_log   enable row level security;

-- settings (same private table the pop-up notifications use). line_quota = messages we allow ourselves per month.
insert into app_private.push_config(k, v) values ('line_fn_url', 'https://eauzvihirpfcjkwyqgel.supabase.co/functions/v1/line') on conflict (k) do nothing;
insert into app_private.push_config(k, v) values ('line_quota', '280') on conflict (k) do nothing;

create or replace function app_private.line_valid_sub(p text) returns boolean
language sql immutable as $$ select p is not null and p ~ '^U[0-9a-f]{32}$' $$;

-- asks the line function to do something; never raises (returns false when it could not be asked)
create or replace function app_private.line_fire(p_body jsonb) returns boolean
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare s text; u text;
begin
  select pc.v into s from app_private.push_config pc where pc.k = 'secret';
  select pc.v into u from app_private.push_config pc where pc.k = 'line_fn_url';
  if s is null or u is null then return false; end if;
  begin
    perform net.http_post(u, p_body, '{}'::jsonb, jsonb_build_object('Content-Type', 'application/json', 'x-push-secret', s), 8000);
    return true;
  exception when others then
    return false;
  end;
end $$;

-- a new notice row -> a LINE message (only when that person has the account linked and the Official Account added)
create or replace function app_private.line_on_notif() returns trigger
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
begin
  begin
    if exists (select 1 from app_private.line_link l where l.uid = new.value->>'userId' and l.friend) then
      perform app_private.line_fire(jsonb_build_object('cmd', 'notif', 'key', new.key));
    end if;
  exception when others then
    null;   -- a LINE problem must never stop the notice itself from being saved
  end;
  return new;
end $$;

drop trigger if exists kv_store_line_notif on public.kv_store;
create trigger kv_store_line_notif after insert on public.kv_store
  for each row when (new.key like 'notif:%') execute function app_private.line_on_notif();

-- ---------------------------------------------------------------------
-- doors for the line function (all need the secret that only the database and the function know)
-- ---------------------------------------------------------------------
-- sign in with a LINE user id the function has already checked with LINE.
--   p_role  : 'customer' | 'trainer' | null (null = whichever account is linked)
--   p_create: a customer who has no account yet may be made from the LINE name (only when the person chose that)
create or replace function public.app_line_login(p_secret text, p_sub text, p_name text, p_role text default null, p_create boolean default false,
                                                 p_friend boolean default null, p_dev text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare l app_private.line_link%rowtype; v jsonb; tok text; created boolean := false; nm text; id text; k text; h text;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.line_valid_sub(p_sub) or (p_role is not null and p_role not in ('customer', 'trainer')) then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('ll:' || left(app_private.sha(p_sub), 16), 600, 40);
  perform app_private.rate_hit('ll:all', 600, 3000);
  select * into l from app_private.line_link x where x.line_sub = p_sub and (p_role is null or x.role = p_role)
   order by (x.role = 'customer') desc, x.last_login desc limit 1;
  if found then
    select value into v from public.kv_store where key = l.ukey;
    if v is null then
      delete from app_private.line_link where line_sub = l.line_sub and role = l.role;   -- the account is gone
      l := null;
    elsif coalesce(v->>'status', '') <> 'active' then
      return jsonb_build_object('ok', false, 'reason', 'suspended');
    end if;
  end if;
  if l.line_sub is null then
    if p_role = 'trainer' then return jsonb_build_object('ok', false, 'reason', 'none'); end if;
    -- a customer made from this LINE user earlier (the link may have been lost in a restore): same id every time
    id := 'cl_' || substr(app_private.sha('line:' || p_sub), 1, 14);
    k := 'customer:' || id;
    select value into v from public.kv_store where key = k;
    if v is not null then
      if coalesce(v->>'status', '') <> 'active' then return jsonb_build_object('ok', false, 'reason', 'suspended'); end if;
    elsif coalesce(p_create, false) then
      perform app_private.rate_hit('reg:' || app_private.client_ip(), 3600, 10);
      perform app_private.rate_hit('reg:all', 3600, 300);
      nm := app_private.clean_text(p_name, 60);
      if nm = '' then nm := 'LINE user'; end if;
      v := jsonb_build_object('id', id, 'username', 'line:' || substr(app_private.sha(p_sub), 1, 16), 'name', nm, 'phone', '', 'authProvider', 'line',
                              'status', 'active', 'role', 'customer', 'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
      insert into public.kv_store(key, value) values (k, v);
      created := true;
    else
      return jsonb_build_object('ok', false, 'reason', 'none');
    end if;
    insert into app_private.line_link(line_sub, role, uid, ukey, name, friend)
    values (p_sub, 'customer', id, k, left(app_private.clean_text(p_name, 60), 60), coalesce(p_friend, false))
    on conflict (line_sub, role) do update set uid = excluded.uid, ukey = excluded.ukey, last_login = now();
    select * into l from app_private.line_link x where x.line_sub = p_sub and x.role = 'customer';
  else
    update app_private.line_link set last_login = now(), friend = coalesce(p_friend, friend) where line_sub = l.line_sub and role = l.role;
  end if;
  tok := app_private.session_new(l.role, l.uid, l.ukey, coalesce(nullif(left(p_dev, 80), ''), 'line'));
  perform app_private.audit(l.ukey, case when created then 'register_line' else 'login_line' end, l.role, true, null);
  perform app_private.maintenance_if_due();
  return jsonb_build_object('ok', true, 'token', tok, 'created', created, 'role', l.role, 'user', app_private.user_out(l.ukey, v),
                            'friend', coalesce(p_friend, l.friend));
end $$;

-- a person who is already signed in (p_token = our own sign-in) attaches the LINE user the function has checked
create or replace function public.app_line_link(p_secret text, p_token text, p_sub text, p_name text, p_friend boolean default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t; had text;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  c := app_private.ctx(p_token);
  if c.role not in ('customer', 'trainer') then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.line_valid_sub(p_sub) then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('lk:' || c.ukey, 3600, 30);
  if exists (select 1 from app_private.line_link where line_sub = p_sub and role = c.role and ukey <> c.ukey) then
    return jsonb_build_object('ok', false, 'reason', 'taken');       -- this LINE user already belongs to another account of the same kind
  end if;
  select line_sub into had from app_private.line_link where ukey = c.ukey;
  if had is not null and had <> p_sub then return jsonb_build_object('ok', false, 'reason', 'other'); end if;   -- this account has another LINE user: unlink first
  insert into app_private.line_link(line_sub, role, uid, ukey, name, friend)
  values (p_sub, c.role, c.uid, c.ukey, left(app_private.clean_text(p_name, 60), 60), coalesce(p_friend, false))
  on conflict (line_sub, role) do update set last_login = now(), friend = coalesce(p_friend, app_private.line_link.friend);
  perform app_private.audit(c.ukey, 'line_link', null, true, null);
  return jsonb_build_object('ok', true, 'role', c.role, 'new', had is null);
end $$;

-- the Official Account was added (true) or blocked (false) by this LINE user
create or replace function public.app_line_friend(p_secret text, p_sub text, p_friend boolean) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare n int;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.line_valid_sub(p_sub) then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('lf', 60, 3000);
  update app_private.line_link set friend = coalesce(p_friend, false) where line_sub = p_sub;
  get diagnostics n = row_count;
  return jsonb_build_object('ok', true, 'linked', n);
end $$;

-- what to send for one notice: who (LINE user ids), the words, and whether this month's allowance is used up
create or replace function public.app_line_take(p_secret text, p_key text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare nv jsonb; subs jsonb; cur_ym text := to_char(now() at time zone 'Asia/Bangkok', 'YYYY-MM'); used int := 0; quota int := 280; q text;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('ltake', 60, 3000);
  if p_key is null or p_key !~ '^notif:[A-Za-z0-9_.@-]{1,80}$' then perform app_private.err(400, 'invalid'); end if;
  select value into nv from public.kv_store where key = p_key;
  if nv is null then return jsonb_build_object('to', '[]'::jsonb, 'over', false); end if;
  select u.n into used from app_private.line_usage u where u.ym = cur_ym;
  used := coalesce(used, 0);
  select pc.v into q from app_private.push_config pc where pc.k = 'line_quota';
  if q ~ '^[0-9]{1,6}$' then quota := q::int; end if;
  select coalesce(jsonb_agg(l.line_sub), '[]'::jsonb) into subs from app_private.line_link l where l.uid = nv->>'userId' and l.friend;
  return jsonb_build_object('to', case when used >= quota then '[]'::jsonb else subs end, 'over', used >= quota, 'used', used,
                            'title', nv->>'title', 'body', nv->>'message', 'id', substr(p_key, 7));
end $$;

-- the function reports what it did (kind 'notif' counts toward the month's allowance; other kinds are just written to the log)
create or replace function public.app_line_done(p_secret text, p_kind text, p_ref text, p_sent int, p_failed int, p_detail text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare cur_ym text := to_char(now() at time zone 'Asia/Bangkok', 'YYYY-MM');
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('ldone', 60, 3000);
  if p_kind = 'notif' and coalesce(p_sent, 0) > 0 then
    insert into app_private.line_usage(ym, n) values (cur_ym, p_sent) on conflict (ym) do update set n = app_private.line_usage.n + excluded.n;
    delete from app_private.line_usage where ym < to_char((now() at time zone 'Asia/Bangkok') - interval '14 months', 'YYYY-MM');
  end if;
  insert into app_private.line_log(kind, ref, sent, failed, detail) values (left(p_kind, 20), left(p_ref, 90), p_sent, p_failed, left(p_detail, 300));
  delete from app_private.line_log where id in (select ll.id from app_private.line_log ll order by ll.id desc offset 300);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- doors for the website (signed-in people)
-- ---------------------------------------------------------------------
create or replace function public.app_line_status(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); l app_private.line_link%rowtype;
begin
  select * into l from app_private.line_link x where x.ukey = c.ukey;
  return jsonb_build_object('ok', true, 'linked', l.line_sub is not null, 'friend', coalesce(l.friend, false));
end $$;

create or replace function public.app_line_unlink(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); v jsonb; sub text;
begin
  if c.role not in ('customer', 'trainer') then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('lu:' || c.ukey, 3600, 20);
  select value into v from public.kv_store where key = c.ukey;
  -- an account made from LINE and with no password would be lost for good: it cannot be unlinked
  if v->>'authProvider' = 'line' and not exists (select 1 from app_private.cred where ukey = c.ukey) then
    return jsonb_build_object('ok', false, 'reason', 'only_line');
  end if;
  delete from app_private.line_link where ukey = c.ukey returning line_sub into sub;
  if sub is not null then perform app_private.line_fire(jsonb_build_object('cmd', 'menu_clear', 'sub', sub)); end if;
  perform app_private.audit(c.ukey, 'line_unlink', null, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- the admin's numbers: linked people, how many have the Official Account, this month's messages and the allowance
create or replace function public.app_line_admin(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); cur_ym text := to_char(now() at time zone 'Asia/Bangkok', 'YYYY-MM'); q text; quota int := 280;
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('lstats:' || c.ukey, 60, 60);
  select pc.v into q from app_private.push_config pc where pc.k = 'line_quota';
  if q ~ '^[0-9]{1,6}$' then quota := q::int; end if;
  return jsonb_build_object('ok', true,
    'linked',  (select count(*) from app_private.line_link),
    'friends', (select count(*) from app_private.line_link where friend),
    'month',   coalesce((select n from app_private.line_usage where ym = cur_ym), 0),
    'quota',   quota);
end $$;

-- the two chat menus the line function made (it stores their ids here, and reads them back when someone signs in)
create or replace function public.app_line_conf(p_secret text, p_menu_customer text default null, p_menu_trainer text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare mc text; mt text;
begin
  if not app_private.push_secret_ok(p_secret) then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('lconf', 60, 600);
  if p_menu_customer is not null then
    if p_menu_customer !~ '^richmenu-[0-9a-f]{32}$' then perform app_private.err(400, 'invalid'); end if;
    insert into app_private.push_config(k, v) values ('line_menu_customer', p_menu_customer)
    on conflict (k) do update set v = excluded.v, updated_at = now();
  end if;
  if p_menu_trainer is not null then
    if p_menu_trainer !~ '^richmenu-[0-9a-f]{32}$' then perform app_private.err(400, 'invalid'); end if;
    insert into app_private.push_config(k, v) values ('line_menu_trainer', p_menu_trainer)
    on conflict (k) do update set v = excluded.v, updated_at = now();
  end if;
  select pc.v into mc from app_private.push_config pc where pc.k = 'line_menu_customer';
  select pc.v into mt from app_private.push_config pc where pc.k = 'line_menu_trainer';
  return jsonb_build_object('menuCustomer', mc, 'menuTrainer', mt);
end $$;

-- ---------------------------------------------------------------------
-- run by the owner in the SQL editor (not reachable from the web)
--   select app_private.line_show_secret();   -- shows the shared secret once, to paste into the function's secrets as DB_SECRET
--   select app_private.line_ping();          -- checks the connection to LINE; then:  select * from app_private.line_log order by id desc limit 5;
--   select app_private.line_setup();         -- makes the two chat menus
-- ---------------------------------------------------------------------
create or replace function app_private.line_show_secret() returns text
language sql security definer set search_path = pg_catalog, public, app_private as $$
  select pc.v from app_private.push_config pc where pc.k = 'secret'
$$;
create or replace function app_private.line_ping() returns text
language sql security definer set search_path = pg_catalog, public, app_private, extensions as $$
  select case when app_private.line_fire(jsonb_build_object('cmd', 'ping'))
              then 'asked - wait 15 seconds, then run:  select * from app_private.line_log order by id desc limit 5;'
              else 'could not reach the line function (is it deployed?)' end
$$;
create or replace function app_private.line_setup() returns text
language sql security definer set search_path = pg_catalog, public, app_private, extensions as $$
  select case when app_private.line_fire(jsonb_build_object('cmd', 'setup'))
              then 'asked - wait 20 seconds, then run:  select * from app_private.line_log order by id desc limit 5;'
              else 'could not reach the line function (is it deployed?)' end
$$;

-- =====================================================================
-- part 7b: the person's own data: agreeing to the terms, and deleting their own account
-- =====================================================================
-- which version of the terms / privacy notice a person agreed to (the version is the date the texts were last changed)
create table if not exists app_private.consent (
  ukey text primary key,
  ver  text not null,
  at   timestamptz not null default now()
);
alter table app_private.consent enable row level security;

-- p_ver null: tells which version this person agreed to (null = never). p_ver given: records the agreement.
create or replace function public.app_consent(p_token text, p_ver text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); cur text;
begin
  if p_ver is null then
    select ver into cur from app_private.consent where ukey = c.ukey;
    return jsonb_build_object('ok', true, 'ver', cur);
  end if;
  if p_ver !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('cons:' || c.ukey, 3600, 30);
  insert into app_private.consent(ukey, ver) values (c.ukey, p_ver)
  on conflict (ukey) do update set ver = excluded.ver, at = now();
  perform app_private.audit(c.ukey, 'consent', p_ver, true, null);
  return jsonb_build_object('ok', true, 'ver', p_ver);
end $$;

-- a customer deletes their own account.
--   * what is personal goes: the profile (name, phone, picture, health notes), password, sign-ins, LINE link, pop-up devices, notices, payment slips
--   * what the trainers still need for their own records stays, with no name and no link to the person:
--     sessions, package and payment records now belong to "a customer who deleted the account"
--   * open bookings are cancelled (the trainer is told); packages with sessions left are closed
create or replace function public.app_delete_account(p_token text, p_pw text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare
  c app_private.ctx_t := app_private.ctx(p_token); v jsonb; h text; sub text;
  ghost text := 'cx_' || app_private.rand_hex(8); gkey text; gname text := 'ลูกค้าที่ลบบัญชีแล้ว'; now_s text;
  r record; nid text; ds text;
begin
  if c.role <> 'customer' then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('del:' || c.ukey, 3600, 10);
  select value into v from public.kv_store where key = c.ukey for update;
  if v is null then perform app_private.err(401, 'unauthenticated'); end if;
  select pw_hash into h from app_private.cred where ukey = c.ukey;
  if h is not null then
    if coalesce(p_pw, '') = '' or length(p_pw) > 200 or extensions.crypt(p_pw, h) <> h then
      return jsonb_build_object('ok', false, 'reason', 'wrong');
    end if;
  end if;
  now_s := to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
  gkey := 'customer:' || ghost;

  -- 1. open bookings are cancelled and the trainer is told
  for r in select key, value from public.kv_store
            where key like 'booking:%' and value->>'customerId' = c.uid and value->>'status' in ('pending', 'confirmed') order by key limit 200 loop
    update public.kv_store set value = value || jsonb_build_object('status', 'cancelled'), updated_at = now() where key = r.key;
    nid := 'notif_' || substr(md5(random()::text || clock_timestamp()::text || r.key), 1, 16);
    ds := extract(day from (r.value->>'bookingDate')::date)::int::text || ' ' ||
          (array['ม.ค.','ก.พ.','มี.ค.','เม.ย.','พ.ค.','มิ.ย.','ก.ค.','ส.ค.','ก.ย.','ต.ค.','พ.ย.','ธ.ค.'])[extract(month from (r.value->>'bookingDate')::date)::int];
    insert into public.kv_store(key, value, updated_at) values ('notif:' || nid, jsonb_build_object(
      'id', nid, 'userId', r.value->>'trainerId', 'title', 'การจองถูกยกเลิก',
      'message', 'ลูกค้าลบบัญชี การจองวันที่ ' || ds || ' เวลา ' || (r.value->>'bookingTime') || ' ถูกยกเลิกแล้ว',
      'isRead', false, 'createdAt', now_s, 'bookingId', r.value->>'id'), now());
  end loop;
  -- 2. packages with sessions left are closed, orders waiting for approval are cancelled
  update public.kv_store set value = value || jsonb_build_object('status', 'cancelled'), updated_at = now()
   where key like 'custpkg:%' and value->>'customerId' = c.uid and value->>'status' = 'active';
  update public.kv_store set value = value || jsonb_build_object('status', 'cancelled'), updated_at = now()
   where key like 'order:%' and value->>'customerId' = c.uid and value->>'status' = 'pending';
  -- 3. payment slips (pictures of bank apps) are removed
  delete from public.kv_store where key like 'slip:%' and value->>'customerId' = c.uid;
  -- 4. what the trainers keep now belongs to the "deleted customer" (a new id nobody can sign in to)
  insert into public.kv_store(key, value, updated_at) values (gkey, jsonb_build_object(
    'id', ghost, 'username', 'deleted:' || ghost, 'name', gname, 'phone', '', 'status', 'deleted', 'role', 'customer', 'createdAt', now_s, 'deletedAt', now_s), now());
  update public.kv_store set value = value || jsonb_build_object('customerId', ghost, 'customerName', gname), updated_at = now()
   where (key like 'booking:%' or key like 'order:%' or key like 'custpkg:%') and value->>'customerId' = c.uid;
  perform app_private.propagate_name('customer', ghost, gname);
  -- 5. notices, devices, LINE, sign-ins, password, the profile itself
  delete from public.kv_store where key like 'notif:%' and value->>'userId' = c.uid;
  delete from app_private.push_subs where user_id = c.uid;
  select l.line_sub into sub from app_private.line_link l where l.ukey = c.ukey;
  if sub is not null then perform app_private.line_fire(jsonb_build_object('cmd', 'menu_clear', 'sub', sub)); end if;
  delete from app_private.line_link where ukey = c.ukey;
  delete from app_private.consent where ukey = c.ukey;
  delete from app_private.session where ukey = c.ukey;
  delete from app_private.cred where ukey = c.ukey;
  delete from public.kv_store where key = c.ukey;
  perform app_private.audit('deleted:' || ghost, 'delete_account', null, true, null);
  return jsonb_build_object('ok', true);
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
              'app_push_config','app_push_wake','app_push_subscribe','app_push_unsubscribe','app_push_take','app_push_vapid_set','app_push_done',
              'app_line_login','app_line_link','app_line_friend','app_line_take','app_line_done','app_line_conf','app_line_status','app_line_unlink','app_line_admin',
              'app_consent','app_delete_account') loop
    execute format('grant execute on function %s to anon, authenticated', f.sig);
  end loop;
end $$;

-- make the API pick up the changes straight away
notify pgrst, 'reload schema';

-- result: every line should say ok
select 'LINE accounts table' as item,
       case when to_regclass('app_private.line_link') is not null then 'ok' else 'MISSING' end as result
union all
select 'trigger on new notices (LINE)', case when exists (select 1 from pg_trigger where tgname = 'kv_store_line_notif') then 'ok' else 'MISSING' end
union all
select 'record of accepted terms', case when to_regclass('app_private.consent') is not null then 'ok' else 'MISSING' end
union all
select 'doors for the website and the function',
       case when (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                   where n.nspname = 'public' and p.proname in ('app_line_login','app_line_link','app_line_friend','app_line_take','app_line_done','app_line_conf',
                                                                'app_line_status','app_line_unlink','app_line_admin','app_consent','app_delete_account')) = 11
            then 'ok' else 'MISSING' end
union all
select 'shared secret for the function', case when exists (select 1 from app_private.push_config pc where pc.k = 'secret') then 'ok' else 'MISSING' end;
