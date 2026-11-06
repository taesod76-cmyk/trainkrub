-- =====================================================================
-- TRAINKRUB security step 1: install the new sign-in and permission system
-- Safe to run more than once. The website keeps working while this runs.
-- =====================================================================
-- =====================================================================
-- TRAINKRUB security layer, part 1: private tables and helpers
-- Safe to run more than once.
-- =====================================================================
create extension if not exists pgcrypto with schema extensions;

create schema if not exists app_private;
revoke all on schema app_private from public;
do $$ begin
  -- the API roles must not be able to look inside the private schema
  begin execute 'revoke all on schema app_private from anon'; exception when others then null; end;
  begin execute 'revoke all on schema app_private from authenticated'; exception when others then null; end;
end $$;

-- ---- passwords (bcrypt hashes only; never in the kv_store JSON) ----
create table if not exists app_private.cred (
  ukey       text primary key,                 -- e.g. customer:c_ab12  trainer:t_x  trainerApp:app_x  admin:admin
  pw_hash    text not null,
  updated_at timestamptz not null default now()
);
-- ---- logins: only a SHA-256 of the token is stored, so a copy of the table cannot be replayed ----
create table if not exists app_private.session (
  id         text primary key,
  ukey       text not null,
  role       text not null,
  uid        text not null,
  created_at timestamptz not null default now(),
  last_seen  timestamptz not null default now(),
  expires_at timestamptz not null,
  dev        text
);
create index if not exists session_ukey_idx on app_private.session (ukey);
create index if not exists session_exp_idx  on app_private.session (expires_at);
-- ---- wrong-password counters and temporary locks ----
create table if not exists app_private.fail (
  bucket       text primary key,
  n            int  not null default 0,
  strikes      int  not null default 0,
  first_at     timestamptz not null default now(),
  locked_until timestamptz
);
-- ---- a Google identity waiting for its trainer application to be filled in (single use, 30 minutes) ----
create table if not exists app_private.ticket (
  id         text primary key,
  gid        text not null,
  email      text,
  name       text,
  expires_at timestamptz not null
);
-- ---- request counters (rate limits) ----
create table if not exists app_private.rate (
  bucket text   not null,
  win    bigint not null,
  n      int    not null default 0,
  primary key (bucket, win)
);
-- ---- security log (kept 180 days) ----
create table if not exists app_private.audit (
  id     bigserial primary key,
  at     timestamptz not null default now(),
  actor  text,
  action text not null,
  target text,
  ok     boolean,
  ip     text,
  detail text
);
create index if not exists audit_at_idx on app_private.audit (at);

alter table app_private.cred    enable row level security;
alter table app_private.session enable row level security;
alter table app_private.fail    enable row level security;
alter table app_private.rate    enable row level security;
alter table app_private.ticket  enable row level security;
alter table app_private.audit   enable row level security;

-- indexes the permission checks lean on
create index if not exists kv_store_username_idx   on public.kv_store ((value->>'username'));
create index if not exists kv_store_phone_idx      on public.kv_store ((value->>'phone'));
create index if not exists kv_store_trainerid_idx  on public.kv_store ((value->>'trainerId'));
create index if not exists kv_store_customerid_idx on public.kv_store ((value->>'customerId'));
create index if not exists kv_store_userid_idx     on public.kv_store ((value->>'userId'));
create index if not exists kv_store_googleid_idx   on public.kv_store ((value->>'googleId'));

-- ---------------------------------------------------------------------
-- small helpers
-- ---------------------------------------------------------------------
do $$ begin
  if not exists (select 1 from pg_type t join pg_namespace n on n.oid=t.typnamespace where n.nspname='app_private' and t.typname='ctx_t') then
    create type app_private.ctx_t as (role text, uid text, ukey text);
  end if;
end $$;

-- PostgREST turns an error whose code is PTnnn into HTTP status nnn
create or replace function app_private.err(p_status int, p_msg text) returns void
language plpgsql as $$
begin
  raise exception '%', p_msg using errcode = 'PT' || p_status::text;
end $$;

create or replace function app_private.client_ip() returns text
language plpgsql stable as $$
declare h jsonb; ip text;
begin
  begin h := nullif(current_setting('request.headers', true), '')::jsonb; exception when others then h := null; end;
  if h is null then return 'local'; end if;
  ip := coalesce(nullif(h->>'cf-connecting-ip',''),
                 nullif(btrim(split_part(coalesce(h->>'x-forwarded-for',''), ',', 1)),''),
                 nullif(h->>'x-real-ip',''), 'unknown');
  return left(btrim(ip), 64);
end $$;

create or replace function app_private.today() returns date
language sql stable as $$ select (now() at time zone 'Asia/Bangkok')::date $$;

create or replace function app_private.clean_text(p text, p_max int) returns text
language sql immutable as $$
  select left(regexp_replace(btrim(coalesce(p,'')), '[\x01-\x08\x0B\x0C\x0E-\x1F\x7F]', '', 'g'), p_max)
$$;

create or replace function app_private.rand_hex(p_bytes int) returns text
language sql volatile as $$ select encode(extensions.gen_random_bytes(p_bytes), 'hex') $$;

create or replace function app_private.sha(p text) returns text
language sql immutable as $$ select encode(extensions.digest(p, 'sha256'), 'hex') $$;

create or replace function app_private.is_data_url(p text, p_max int) returns boolean
language sql immutable as $$
  select p is not null and length(p) <= p_max and p ~ '^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$'
$$;

-- true when old and new are identical once the listed keys are ignored
create or replace function app_private.same_except(p_old jsonb, p_new jsonb, p_keys text[]) returns boolean
language sql immutable as $$ select (p_old - p_keys) = (p_new - p_keys) $$;

create or replace function app_private.audit(p_actor text, p_action text, p_target text, p_ok boolean, p_detail text default null) returns void
language plpgsql as $$
begin
  insert into app_private.audit(actor, action, target, ok, ip, detail)
  values (left(p_actor,80), left(p_action,60), left(p_target,120), p_ok, app_private.client_ip(), left(p_detail,300));
end $$;

-- ---- rate limit: raises 429 when more than p_limit hits land in the same time window ----
create or replace function app_private.rate_hit(p_bucket text, p_window_sec int, p_limit int) returns void
language plpgsql as $$
declare w bigint := floor(extract(epoch from now()) / p_window_sec)::bigint; c int;
begin
  insert into app_private.rate(bucket, win, n) values (p_bucket, w, 1)
  on conflict (bucket, win) do update set n = app_private.rate.n + 1
  returning n into c;
  if c > p_limit then perform app_private.err(429, 'rate_limited'); end if;
end $$;

-- ---- wrong-password locks ----
create or replace function app_private.lock_left(p_bucket text) returns int
language sql stable as $$
  select coalesce((select greatest(0, ceil(extract(epoch from (locked_until - now())))::int)
                   from app_private.fail where bucket = p_bucket and locked_until is not null), 0)
$$;

create or replace function app_private.lock_fail(p_bucket text, p_max int, p_lock_sec int, p_window_sec int) returns void
language plpgsql as $$
declare r app_private.fail%rowtype;
begin
  insert into app_private.fail(bucket, n, first_at) values (p_bucket, 1, now())
  on conflict (bucket) do update set
    n        = case when app_private.fail.first_at < now() - make_interval(secs => p_window_sec) then 1 else app_private.fail.n + 1 end,
    first_at = case when app_private.fail.first_at < now() - make_interval(secs => p_window_sec) then now() else app_private.fail.first_at end
  returning * into r;
  if r.n >= p_max then
    -- every lock doubles the next one (up to 24 hours); a good login clears the slate
    update app_private.fail
       set locked_until = now() + make_interval(secs => least(p_lock_sec * power(2, r.strikes), 86400)),
           strikes = r.strikes + 1, n = 0, first_at = now()
     where bucket = p_bucket;
  end if;
end $$;

create or replace function app_private.lock_clear(p_bucket text) returns void
language sql as $$ delete from app_private.fail where bucket = p_bucket $$;

-- ---- sessions ----
create or replace function app_private.session_new(p_role text, p_uid text, p_ukey text, p_dev text) returns text
language plpgsql as $$
declare tok text := app_private.rand_hex(32);
begin
  delete from app_private.session where ukey = p_ukey and expires_at <= now();
  -- at most 8 live logins per account: the oldest ones are dropped
  delete from app_private.session where id in
    (select id from app_private.session where ukey = p_ukey order by last_seen desc offset 7);
  insert into app_private.session(id, ukey, role, uid, expires_at, dev)
  values (app_private.sha(tok), p_ukey, p_role, p_uid, now() + interval '90 days', left(coalesce(p_dev,''), 80));
  return tok;
end $$;

-- who is calling? raises 401 when the token is unknown, expired, or the account was suspended/removed
create or replace function app_private.ctx(p_token text) returns app_private.ctx_t
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare s app_private.session%rowtype; v jsonb; c app_private.ctx_t;
begin
  if p_token is null or length(p_token) < 40 or length(p_token) > 200 then perform app_private.err(401, 'unauthenticated'); end if;
  select * into s from app_private.session where id = app_private.sha(p_token) and expires_at > now();
  if not found then perform app_private.err(401, 'unauthenticated'); end if;
  select value into v from public.kv_store where key = s.ukey;
  if v is null or (s.role <> 'admin' and coalesce(v->>'status','') <> 'active') then
    perform app_private.err(401, 'unauthenticated');
  end if;
  if s.last_seen < now() - interval '1 hour' then
    update app_private.session
       set last_seen = now(), expires_at = least(now() + interval '90 days', s.created_at + interval '365 days')
     where id = s.id;
  end if;
  c.role := s.role; c.uid := s.uid; c.ukey := s.ukey;
  return c;
end $$;

-- name used for a user (for messages and denormalised copies)
create or replace function app_private.display_name(p_key text) returns text
language sql stable as $$ select value->>'name' from public.kv_store where key = p_key $$;
-- =====================================================================
-- part 2: sign in, sign up, Google, passwords, trainer sign-up (accepted automatically)
-- Every function here is the ONLY way these things can happen: the browser
-- cannot read or write the data tables directly any more.
-- =====================================================================

create or replace function app_private.valid_password(p_pw text, p_phone text default null) returns boolean
language sql immutable as $$
  select p_pw is not null
     and length(p_pw) between 8 and 128
     and lower(p_pw) not in ('12345678','123456789','1234567890','11111111','00000000','password','password1','qwertyui','qwerty123','abcd1234','iloveyou','12341234')
     and p_pw is distinct from p_phone
$$;

create or replace function app_private.valid_phone(p text) returns boolean
language sql immutable as $$ select p ~ '^[0-9+()\- ]{6,20}$' $$;

-- a verified Google identity, or null. PostgREST has already checked the signature of the token.
create or replace function app_private.google_claims() returns jsonb
language plpgsql stable as $$
declare c jsonb; nm text;
begin
  begin c := nullif(current_setting('request.jwt.claims', true), '')::jsonb; exception when others then return null; end;
  if c is null or c->>'role' is distinct from 'authenticated' or coalesce(c->>'sub','') = '' then return null; end if;
  if not ( coalesce(c->'app_metadata'->>'provider','') = 'google'
           or (jsonb_typeof(c->'app_metadata'->'providers') = 'array' and (c->'app_metadata'->'providers') ? 'google') ) then
    return null;
  end if;
  nm := coalesce(nullif(c->'user_metadata'->>'full_name',''), nullif(c->'user_metadata'->>'name',''), '');
  return jsonb_build_object('sub', c->>'sub', 'email', lower(coalesce(c->>'email','')), 'name', nm);
end $$;

create or replace function app_private.user_out(p_key text, v jsonb) returns jsonb
language sql immutable as $$
  select jsonb_build_object('id', case when split_part(p_key,':',1) = 'admin' then 'admin' else v->>'id' end,
                            'role', split_part(p_key,':',1),
                            'name', coalesce(v->>'name',''))
$$;

-- ---------------------------------------------------------------------
-- sign in with a password
-- ---------------------------------------------------------------------
create or replace function public.app_login(p_role text, p_id text, p_pw text, p_dev text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare
  v_id text := left(btrim(coalesce(p_id,'')), 100);
  b_acct text; b_ip text; lk int;
  r_key text; r_val jsonb; h text; ok boolean := false; tok text;
  a_key text; a_h text;
  max_fail int;
begin
  if p_role not in ('customer','trainer','admin') or v_id = '' or coalesce(p_pw,'') = '' or length(p_pw) > 200 then
    return jsonb_build_object('ok', false, 'reason', 'wrong');
  end if;
  b_acct := 'a:' || p_role || ':' || lower(v_id);
  b_ip   := 'i:' || app_private.client_ip();
  lk := greatest(app_private.lock_left(b_acct), app_private.lock_left(b_ip));
  if lk > 0 then return jsonb_build_object('ok', false, 'reason', 'locked', 'retry', lk); end if;

  if p_role = 'admin' then
    select key, value into r_key, r_val from public.kv_store where key = 'admin:admin' and value->>'username' = v_id;
  else
    select key, value into r_key, r_val from public.kv_store
     where key like p_role || ':%' and (value->>'username' = v_id or value->>'phone' = v_id)
     order by key limit 1;
  end if;

  if r_key is not null then select pw_hash into h from app_private.cred where ukey = r_key; end if;
  if h is not null then
    ok := (extensions.crypt(p_pw, h) = h);
  else
    perform extensions.crypt(p_pw, extensions.gen_salt('bf', 10));   -- same work whether or not the account exists
  end if;

  if not ok and p_role = 'trainer' then
    -- an application that was never finished (the page was closed half way, or it is an older one): whoever proves
    -- the password is the applicant, so the application is accepted now and they are signed in
    select key into a_key from public.kv_store
     where key like 'trainerApp:%' and (value->>'username' = v_id or value->>'phone' = v_id) limit 1;
    if a_key is not null then
      select pw_hash into a_h from app_private.cred where ukey = a_key;
      if a_h is not null and extensions.crypt(p_pw, a_h) = a_h then
        r_key := app_private.approve_app(a_key);
        if r_key is not null then
          select value into r_val from public.kv_store where key = r_key;
          ok := true;
        end if;
      end if;
    end if;
  end if;
  if not ok then
    max_fail := case when p_role = 'admin' then 5 else 8 end;
    perform app_private.lock_fail(b_acct, max_fail, 900, 900);
    perform app_private.lock_fail(b_ip, 40, 1800, 900);
    perform app_private.audit(v_id, 'login_fail', p_role, false, null);
    return jsonb_build_object('ok', false, 'reason', 'wrong');
  end if;

  if p_role <> 'admin' and coalesce(r_val->>'status','') <> 'active' then
    return jsonb_build_object('ok', false, 'reason', 'suspended');
  end if;
  perform app_private.lock_clear(b_acct);
  tok := app_private.session_new(p_role, case when p_role = 'admin' then 'admin' else r_val->>'id' end, r_key, p_dev);
  perform app_private.audit(r_key, 'login', p_role, true, null);
  perform app_private.maintenance_if_due();
  return jsonb_build_object('ok', true, 'token', tok, 'user', app_private.user_out(r_key, r_val));
end $$;

-- is this token still good? (used when the page opens)
create or replace function public.app_whoami(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t; v jsonb;
begin
  begin c := app_private.ctx(p_token);
  exception when sqlstate 'PT401' then return jsonb_build_object('ok', false); end;
  select value into v from public.kv_store where key = c.ukey;
  return jsonb_build_object('ok', true, 'user', app_private.user_out(c.ukey, v));
end $$;

create or replace function public.app_logout(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
begin
  if p_token is not null and length(p_token) between 40 and 200 then
    delete from app_private.session where id = app_private.sha(p_token);
  end if;
  return jsonb_build_object('ok', true);
end $$;

-- sign out everywhere
create or replace function public.app_logout_all(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t;
begin
  c := app_private.ctx(p_token);
  delete from app_private.session where ukey = c.ukey;
  perform app_private.audit(c.ukey, 'logout_all', null, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- customer sign up
-- ---------------------------------------------------------------------
create or replace function public.app_register_customer(p_name text, p_phone text, p_pw text, p_dev text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare nm text := app_private.clean_text(p_name, 60); ph text := app_private.clean_text(p_phone, 20);
        id text; k text; v jsonb; tok text;
begin
  perform app_private.rate_hit('reg:' || app_private.client_ip(), 3600, 10);
  perform app_private.rate_hit('reg:all', 3600, 300);
  if nm = '' or not app_private.valid_phone(ph) then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if not app_private.valid_password(p_pw, ph) then return jsonb_build_object('ok', false, 'reason', 'weak'); end if;
  perform pg_advisory_xact_lock(hashtext('phone:' || ph));
  if exists (select 1 from public.kv_store where key like 'customer:%' and (value->>'phone' = ph or value->>'username' = ph)) then
    return jsonb_build_object('ok', false, 'reason', 'phone_used');
  end if;
  id := 'c_' || app_private.rand_hex(6);
  k := 'customer:' || id;
  v := jsonb_build_object('id', id, 'username', ph, 'name', nm, 'phone', ph, 'status', 'active', 'role', 'customer',
                          'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
  insert into public.kv_store(key, value) values (k, v);
  insert into app_private.cred(ukey, pw_hash) values (k, extensions.crypt(p_pw, extensions.gen_salt('bf', 10)));
  tok := app_private.session_new('customer', id, k, p_dev);
  perform app_private.audit(k, 'register', 'customer', true, null);
  return jsonb_build_object('ok', true, 'token', tok, 'user', app_private.user_out(k, v));
end $$;

-- ---------------------------------------------------------------------
-- trainer application (certificate pictures follow one by one)
-- ---------------------------------------------------------------------
create or replace function public.app_apply_trainer(p_app jsonb, p_pw text, p_ticket text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare
  g jsonb := null; tkt app_private.ticket%rowtype;
  nm text; sp text; ph text; bio text; photo text; certs jsonb := '[]'::jsonb; c jsonb;
  id text; k text; ut text; v jsonb; uname text; n int := 0;
begin
  perform app_private.rate_hit('apply:' || app_private.client_ip(), 3600, 6);
  perform app_private.rate_hit('apply:all', 3600, 100);
  if p_app is null or jsonb_typeof(p_app) <> 'object' then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if p_ticket is not null then
    select * into tkt from app_private.ticket t where t.id = app_private.sha(p_ticket) and t.expires_at > now();
    if not found then return jsonb_build_object('ok', false, 'reason', 'ticket'); end if;
    g := jsonb_build_object('sub', tkt.gid, 'email', coalesce(tkt.email,''), 'name', coalesce(tkt.name,''));
  end if;
  nm := app_private.clean_text(p_app->>'name', 60);
  sp := app_private.clean_text(p_app->>'specialty', 80);
  ph := app_private.clean_text(p_app->>'phone', 20);
  bio := app_private.clean_text(p_app->>'bio', 1000);
  if nm = '' or not app_private.valid_phone(ph) then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if g is null and not app_private.valid_password(p_pw, ph) then return jsonb_build_object('ok', false, 'reason', 'weak'); end if;
  if jsonb_typeof(p_app->'certs') = 'array' then
    for c in select * from jsonb_array_elements(p_app->'certs') loop
      exit when n >= 8;
      if app_private.clean_text(c->>'name', 80) <> '' then
        certs := certs || jsonb_build_array(jsonb_build_object(
          'name', app_private.clean_text(c->>'name', 80), 'issuer', app_private.clean_text(c->>'issuer', 80), 'year', app_private.clean_text(c->>'year', 8)));
        n := n + 1;
      end if;
    end loop;
  end if;
  photo := p_app->>'photo';
  if photo is not null and not app_private.is_data_url(photo, 64000) then photo := null; end if;

  perform pg_advisory_xact_lock(hashtext('phone:' || ph));
  if exists (select 1 from public.kv_store where (key like 'trainer:%' or key like 'trainerApp:%') and (value->>'phone' = ph or value->>'username' = ph)) then
    return jsonb_build_object('ok', false, 'reason', 'phone_used');
  end if;
  if g is not null and exists (select 1 from public.kv_store where (key like 'trainer:%' or key like 'trainerApp:%') and value->>'googleId' = g->>'sub') then
    return jsonb_build_object('ok', false, 'reason', 'exists');
  end if;

  id := 'app_' || app_private.rand_hex(6);
  k := 'trainerApp:' || id;
  ut := app_private.rand_hex(24);
  uname := case when g is not null then 'google:' || (g->>'sub') else ph end;
  v := jsonb_build_object('id', id, 'username', uname, 'name', nm, 'phone', ph, 'specialty', sp, 'bio', bio, 'certs', certs,
                          'submittedAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'status', 'pending',
                          '_ut', app_private.sha(ut));
  if photo is not null then v := v || jsonb_build_object('photo', photo); end if;
  if g is not null then
    v := v || jsonb_build_object('googleId', g->>'sub', 'email', g->>'email', 'authProvider', 'google');
  end if;
  insert into public.kv_store(key, value) values (k, v);
  if g is null then
    insert into app_private.cred(ukey, pw_hash) values (k, extensions.crypt(p_pw, extensions.gen_salt('bf', 10)));
  end if;
  if p_ticket is not null then delete from app_private.ticket t where t.id = app_private.sha(p_ticket); end if;
  perform app_private.audit(k, 'apply', 'trainer', true, null);
  return jsonb_build_object('ok', true, 'appId', id, 'uploadToken', ut);
end $$;

create or replace function public.app_apply_cert(p_app_id text, p_ut text, p_idx int, p_img text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare k text := 'trainerApp:' || coalesce(p_app_id,''); v jsonb; iid text; cert jsonb;
begin
  perform app_private.rate_hit('cert:' || app_private.client_ip(), 3600, 40);
  select value into v from public.kv_store where key = k for update;
  if v is null or coalesce(p_ut,'') = '' or app_private.sha(p_ut) <> coalesce(v->>'_ut','') then
    perform app_private.err(403, 'forbidden');
  end if;
  if p_idx is null or p_idx < 0 or p_idx >= jsonb_array_length(v->'certs') then perform app_private.err(400, 'invalid'); end if;
  if not app_private.is_data_url(p_img, 480000) then perform app_private.err(400, 'invalid_image'); end if;
  cert := v->'certs'->p_idx;
  if cert ? 'imgId' then
    delete from public.kv_store where key = 'certimg:' || (cert->>'imgId');
  end if;
  iid := 'ci_' || app_private.rand_hex(6);
  insert into public.kv_store(key, value) values ('certimg:' || iid,
     jsonb_build_object('data', p_img, 'appId', p_app_id, 'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
  v := jsonb_set(v, array['certs', p_idx::text], cert || jsonb_build_object('imgId', iid));
  update public.kv_store set value = v, updated_at = now() where key = k;
  return jsonb_build_object('ok', true, 'imgId', iid);
end $$;

-- ---------------------------------------------------------------------
-- admin: approve / refuse an application
-- ---------------------------------------------------------------------
create or replace function app_private.new_trainer_code() returns text
language plpgsql as $$
declare chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; code text; i int;
begin
  loop
    code := '';
    for i in 1..4 loop code := code || substr(chars, 1 + floor(random() * 32)::int, 1); end loop;
    exit when not exists (select 1 from public.kv_store where key like 'trainer:%' and value->>'code' = code);
  end loop;
  return code;
end $$;

-- turns an application into a trainer (account, code, certificate pictures). Returns the trainer's key, or null if the application is gone.
create or replace function app_private.approve_app(ak text) returns text
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare a jsonb; tid text; tk text; code text; t jsonb; cert jsonb;
begin
  select value into a from public.kv_store where key = ak for update;
  if a is null then return null; end if;
  tid := 't_' || substr(ak, length('trainerApp:') + 1);
  tk := 'trainer:' || tid;
  code := app_private.new_trainer_code();
  t := jsonb_build_object('id', tid, 'username', a->>'username', 'name', a->>'name', 'phone', a->>'phone',
        'specialty', coalesce(a->>'specialty',''), 'bio', coalesce(a->>'bio',''), 'certs', coalesce(a->'certs','[]'::jsonb),
        'status', 'active', 'ready', true, 'role', 'trainer', 'code', code);
  if a ? 'photo' then t := t || jsonb_build_object('photo', a->'photo'); end if;
  if a ? 'googleId' then
    t := t || jsonb_build_object('googleId', a->'googleId', 'email', coalesce(a->>'email',''));
    if a->>'authProvider' = 'google' then t := t || jsonb_build_object('authProvider', 'google'); end if;
  end if;
  insert into public.kv_store(key, value) values (tk, t);
  update app_private.cred set ukey = tk where ukey = ak;
  -- the certificate pictures now belong to the trainer
  for cert in select * from jsonb_array_elements(coalesce(a->'certs','[]'::jsonb)) loop
    if cert ? 'imgId' then
      update public.kv_store set value = (value - 'appId') || jsonb_build_object('ownerId', tid) where key = 'certimg:' || (cert->>'imgId');
    end if;
  end loop;
  delete from public.kv_store where key = ak;
  return tk;
end $$;

-- admin: accept an application that is still waiting (new applications are accepted automatically)
create or replace function public.app_approve_trainer(p_token text, p_app_id text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); tk text; t jsonb;
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  tk := app_private.approve_app('trainerApp:' || coalesce(p_app_id,''));
  if tk is null then return jsonb_build_object('ok', false, 'reason', 'gone'); end if;
  select value into t from public.kv_store where key = tk;
  perform app_private.audit(c.ukey, 'approve_trainer', tk, true, null);
  return jsonb_build_object('ok', true, 'trainerId', t->>'id', 'code', t->>'code');
end $$;

-- the applicant finishes the application with the one-time upload token: the trainer exists at once and is signed in
create or replace function public.app_finish_apply(p_app_id text, p_ut text, p_dev text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare k text := 'trainerApp:' || coalesce(p_app_id,''); v jsonb; tk text; tv jsonb; tok text;
begin
  perform app_private.rate_hit('finish:' || app_private.client_ip(), 3600, 30);
  select value into v from public.kv_store where key = k for update;
  if v is null or coalesce(p_ut,'') = '' or app_private.sha(p_ut) <> coalesce(v->>'_ut','') then
    perform app_private.err(403, 'forbidden');
  end if;
  tk := app_private.approve_app(k);
  select value into tv from public.kv_store where key = tk;
  tok := app_private.session_new('trainer', tv->>'id', tk, p_dev);
  perform app_private.audit(tk, 'apply_accepted', 'trainer', true, null);
  return jsonb_build_object('ok', true, 'token', tok, 'user', app_private.user_out(tk, tv));
end $$;

create or replace function public.app_reject_trainer(p_token text, p_app_id text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); ak text := 'trainerApp:' || coalesce(p_app_id,''); a jsonb; cert jsonb;
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  select value into a from public.kv_store where key = ak for update;
  if a is null then return jsonb_build_object('ok', false, 'reason', 'gone'); end if;
  for cert in select * from jsonb_array_elements(coalesce(a->'certs','[]'::jsonb)) loop
    if cert ? 'imgId' then delete from public.kv_store where key = 'certimg:' || (cert->>'imgId'); end if;
  end loop;
  delete from public.kv_store where key = ak;
  delete from app_private.cred where ukey = ak;
  perform app_private.audit(c.ukey, 'reject_trainer', ak, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- passwords
-- ---------------------------------------------------------------------
create or replace function public.app_change_password(p_token text, p_old text, p_new text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); h text; v jsonb; b text;
begin
  select value into v from public.kv_store where key = c.ukey;
  select pw_hash into h from app_private.cred where ukey = c.ukey;
  if h is null then return jsonb_build_object('ok', false, 'reason', 'no_password'); end if;
  b := 'p:' || c.ukey;
  if app_private.lock_left(b) > 0 then return jsonb_build_object('ok', false, 'reason', 'locked', 'retry', app_private.lock_left(b)); end if;
  if extensions.crypt(coalesce(p_old,''), h) <> h then
    perform app_private.lock_fail(b, 6, 900, 900);
    return jsonb_build_object('ok', false, 'reason', 'wrong');
  end if;
  if not app_private.valid_password(p_new, v->>'phone') or (c.role = 'admin' and length(p_new) < 12) then
    return jsonb_build_object('ok', false, 'reason', 'weak');
  end if;
  update app_private.cred set pw_hash = extensions.crypt(p_new, extensions.gen_salt('bf', 10)), updated_at = now() where ukey = c.ukey;
  delete from app_private.session where ukey = c.ukey and id <> app_private.sha(p_token);   -- other devices must sign in again
  perform app_private.lock_clear(b);
  perform app_private.audit(c.ukey, 'change_password', null, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- admin sets a new password for someone who forgot theirs
create or replace function public.app_reset_password(p_token text, p_target text, p_new text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); v jsonb; r text;
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  if p_target is null or p_target !~ '^(customer|trainer):[A-Za-z0-9_]{1,60}$' then perform app_private.err(400, 'invalid'); end if;
  select value into v from public.kv_store where key = p_target;
  if v is null then return jsonb_build_object('ok', false, 'reason', 'gone'); end if;
  if v->>'authProvider' = 'google' then return jsonb_build_object('ok', false, 'reason', 'google'); end if;
  if not app_private.valid_password(p_new, v->>'phone') then return jsonb_build_object('ok', false, 'reason', 'weak'); end if;
  insert into app_private.cred(ukey, pw_hash) values (p_target, extensions.crypt(p_new, extensions.gen_salt('bf', 10)))
  on conflict (ukey) do update set pw_hash = excluded.pw_hash, updated_at = now();
  delete from app_private.session where ukey = p_target;
  r := split_part(p_target, ':', 1);
  delete from app_private.fail where bucket in ('a:' || r || ':' || lower(coalesce(v->>'username','')), 'a:' || r || ':' || lower(coalesce(v->>'phone','')));
  perform app_private.audit(c.ukey, 'reset_password', p_target, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- Google
-- (the browser sends the Google-issued token as the Authorization header; the database reads the checked claims)
-- ---------------------------------------------------------------------
create or replace function public.app_google_login(p_role text, p_dev text default null) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare g jsonb := app_private.google_claims(); sub text; k text; v jsonb; id text; nm text; tok text; created boolean := false;
        tk text; tv jsonb; tkt_id text; a_key text;
begin
  if g is null then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  sub := g->>'sub';
  perform app_private.rate_hit('glogin:' || app_private.client_ip(), 600, 30);
  if p_role = 'customer' then
    id := 'cg_' || replace(sub, '-', '');
    k := 'customer:' || id;
    select value into v from public.kv_store where key = k;
    if v is null then
      perform app_private.rate_hit('reg:' || app_private.client_ip(), 3600, 10);
      nm := app_private.clean_text(coalesce(nullif(g->>'name',''), split_part(g->>'email','@',1), ''), 60);
      if nm = '' then nm := 'Google user'; end if;
      v := jsonb_build_object('id', id, 'username', 'google:' || sub, 'name', nm, 'phone', '', 'email', g->>'email', 'googleId', sub,
                              'authProvider', 'google', 'status', 'active', 'role', 'customer',
                              'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
      insert into public.kv_store(key, value) values (k, v);
      created := true;
    elsif coalesce(v->>'status','') <> 'active' then
      return jsonb_build_object('ok', false, 'reason', 'suspended');
    end if;
    tok := app_private.session_new('customer', id, k, p_dev);
    perform app_private.audit(k, case when created then 'register_google' else 'login_google' end, 'customer', true, null);
    return jsonb_build_object('ok', true, 'token', tok, 'created', created, 'user', app_private.user_out(k, v));
  elsif p_role = 'trainer' then
    select key, value into tk, tv from public.kv_store where key like 'trainer:%' and value->>'googleId' = sub limit 1;
    if tk is not null then
      if coalesce(tv->>'status','') <> 'active' then return jsonb_build_object('ok', false, 'reason', 'suspended'); end if;
      tok := app_private.session_new('trainer', tv->>'id', tk, p_dev);
      perform app_private.audit(tk, 'login_google', 'trainer', true, null);
      return jsonb_build_object('ok', true, 'token', tok, 'created', false, 'user', app_private.user_out(tk, tv));
    end if;
    select key into a_key from public.kv_store where key like 'trainerApp:%' and value->>'googleId' = sub limit 1;
    if a_key is not null then
      -- an application of this Google account that was never finished: accept it now
      tk := app_private.approve_app(a_key);
      if tk is not null then
        select value into tv from public.kv_store where key = tk;
        tok := app_private.session_new('trainer', tv->>'id', tk, p_dev);
        perform app_private.audit(tk, 'login_google', 'trainer', true, null);
        return jsonb_build_object('ok', true, 'token', tok, 'created', true, 'user', app_private.user_out(tk, tv));
      end if;
    end if;
    tkt_id := app_private.rand_hex(24);
    delete from app_private.ticket where expires_at <= now();
    insert into app_private.ticket(id, gid, email, name, expires_at)
    values (app_private.sha(tkt_id), sub, left(g->>'email', 200), left(g->>'name', 100), now() + interval '30 minutes');
    return jsonb_build_object('ok', false, 'reason', 'none', 'ticket', tkt_id,
             'applicant', jsonb_build_object('gid', sub, 'email', g->>'email', 'name', g->>'name'));
  end if;
  return jsonb_build_object('ok', false, 'reason', 'invalid');
end $$;

-- a signed-in trainer attaches their Google account (Authorization = the Google token, p_token = our session)
create or replace function public.app_google_link(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); g jsonb := app_private.google_claims(); v jsonb;
begin
  if c.role <> 'trainer' then perform app_private.err(403, 'forbidden'); end if;
  if g is null then return jsonb_build_object('ok', false, 'reason', 'invalid'); end if;
  if exists (select 1 from public.kv_store where (key like 'trainer:%' or key like 'trainerApp:%')
              and value->>'googleId' = g->>'sub' and key <> c.ukey) then
    return jsonb_build_object('ok', false, 'reason', 'taken');
  end if;
  select value into v from public.kv_store where key = c.ukey for update;
  if coalesce(v->>'googleId','') <> '' and v->>'googleId' <> g->>'sub' then
    return jsonb_build_object('ok', false, 'reason', 'other');     -- already linked to a different Google account: unlink first
  end if;
  v := v || jsonb_build_object('googleId', g->>'sub', 'email', g->>'email');
  update public.kv_store set value = v, updated_at = now() where key = c.ukey;
  perform app_private.audit(c.ukey, 'google_link', null, true, null);
  return jsonb_build_object('ok', true, 'email', g->>'email');
end $$;

create or replace function public.app_google_unlink(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); v jsonb;
begin
  if c.role <> 'trainer' then perform app_private.err(403, 'forbidden'); end if;
  select value into v from public.kv_store where key = c.ukey for update;
  if v->>'authProvider' = 'google' or not exists (select 1 from app_private.cred where ukey = c.ukey) then
    return jsonb_build_object('ok', false, 'reason', 'only_google');
  end if;
  update public.kv_store set value = v - 'googleId' - 'email', updated_at = now() where key = c.ukey;
  perform app_private.audit(c.ukey, 'google_unlink', null, true, null);
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- run by the owner in the SQL editor (not reachable from the web):
--   select app_private.admin_set('<new admin name>', '<new long password>');
-- ---------------------------------------------------------------------
create or replace function app_private.admin_set(p_username text, p_password text) returns text
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
begin
  if p_username is null or length(btrim(p_username)) < 4 or length(p_username) > 60 then raise exception 'username must be 4-60 characters'; end if;
  if p_password is null or length(p_password) < 12 or length(p_password) > 128 then raise exception 'password must be 12-128 characters'; end if;
  if not app_private.valid_password(p_password) then raise exception 'password is too common'; end if;
  insert into public.kv_store(key, value)
  values ('admin:admin', jsonb_build_object('username', btrim(p_username), 'name', 'ผู้ดูแลระบบ / System Admin', 'role', 'admin'))
  on conflict (key) do update set value = (public.kv_store.value - 'password') || jsonb_build_object('username', btrim(p_username)), updated_at = now();
  insert into app_private.cred(ukey, pw_hash) values ('admin:admin', extensions.crypt(p_password, extensions.gen_salt('bf', 12)))
  on conflict (ukey) do update set pw_hash = excluded.pw_hash, updated_at = now();
  delete from app_private.session where ukey = 'admin:admin';
  delete from app_private.fail where bucket like 'a:admin:%';
  perform app_private.audit('owner', 'admin_set', 'admin:admin', true, null);
  return 'admin login updated';
end $$;
-- =====================================================================
-- part 3: the permission engine
-- The app still thinks in "keys and values", but every read and write
-- now goes through these functions, which decide who may see or change
-- each row and check that the new value makes sense.
-- =====================================================================

-- does this trainer have any booking / package / order with this customer?
create or replace function app_private.rel_trainer_customer(p_trainer text, p_customer text) returns boolean
language sql stable as $$
  select p_trainer is not null and p_customer is not null and (
       exists (select 1 from public.kv_store where key like 'booking:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer)
    or exists (select 1 from public.kv_store where key like 'custpkg:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer)
    or exists (select 1 from public.kv_store where key like 'order:%'   and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer))
$$;

-- may this trainer see this customer's health information?  Only while they really work together:
-- a package of theirs (not cancelled) or a booking that was not cancelled / refused
create or replace function app_private.trainer_sees_health(p_trainer text, p_customer text) returns boolean
language sql stable as $$
  select p_trainer is not null and p_customer is not null and (
       exists (select 1 from public.kv_store where key like 'custpkg:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer
                 and value->>'status' in ('active','used_up','expired'))
    or exists (select 1 from public.kv_store where key like 'booking:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer
                 and value->>'status' in ('pending','confirmed','completed','no_show')))
$$;

-- a customer may see a trainer only after adding them with the trainer's code (or already having a booking/package/order with them)
create or replace function app_private.customer_knows_trainer(p_customer text, p_trainer text) returns boolean
language sql stable as $$
  select p_customer is not null and p_trainer is not null and (
       exists (select 1 from public.kv_store where key = 'customer:' || p_customer
                 and (value->'myTrainerIds' ? p_trainer or value->'pinnedTrainerIds' ? p_trainer))
    or exists (select 1 from public.kv_store where key like 'booking:%' and value->>'customerId' = p_customer and value->>'trainerId' = p_trainer)
    or exists (select 1 from public.kv_store where key like 'custpkg:%' and value->>'customerId' = p_customer and value->>'trainerId' = p_trainer)
    or exists (select 1 from public.kv_store where key like 'order:%'   and value->>'customerId' = p_customer and value->>'trainerId' = p_trainer))
$$;

create or replace function app_private.trainer_public(v jsonb) returns jsonb
language sql immutable as $$ select v - 'password' - 'username' - 'googleId' - 'email' - 'authProvider' $$;

create or replace function app_private.trainer_is_active(p_trainer text) returns boolean
language sql stable as $$
  select exists (select 1 from public.kv_store where key = 'trainer:' || coalesce(p_trainer,'') and value->>'status' = 'active')
$$;

-- ---------------------------------------------------------------------
-- READ: what may this caller see of this row (null = nothing)
-- ---------------------------------------------------------------------
create or replace function app_private.read_view(c app_private.ctx_t, p_key text, v jsonb) returns jsonb
language plpgsql stable as $$
declare pfx text := split_part(p_key, ':', 1);
begin
  if v is null then return null; end if;
  if pfx = 'admin' then
    if c.role = 'admin' then return v - 'password'; end if;
    return null;
  elsif pfx = 'customer' then
    if c.role = 'admin' then return v - 'password' - 'photo' - 'health'; end if;
    if c.role = 'customer' and v->>'id' = c.uid then return v - 'password'; end if;
    if c.role = 'trainer' and app_private.rel_trainer_customer(c.uid, v->>'id') then
      return jsonb_strip_nulls(jsonb_build_object('id', v->'id', 'name', v->'name', 'phone', v->'phone', 'photo', v->'photo',
                                                   'status', v->'status', 'role', v->'role'))
             || case when coalesce(v->'health'->>'consent', '') = 'true' and app_private.trainer_sees_health(c.uid, v->>'id')
                     then jsonb_build_object('health', v->'health') else '{}'::jsonb end;
    end if;
    return null;
  elsif pfx = 'trainer' then
    if c.role = 'admin' then return v - 'password' - 'photo'; end if;
    if c.role = 'trainer' and v->>'id' = c.uid then return v - 'password'; end if;
    if c.role = 'customer' and v->>'status' = 'active' and app_private.customer_knows_trainer(c.uid, v->>'id') then
      return app_private.trainer_public(v);
    end if;
    return null;
  elsif pfx = 'trainerApp' then
    if c.role = 'admin' then return v - 'password' - '_ut'; end if;
    return null;
  elsif pfx = 'booking' then
    if c.role = 'admin' then return v; end if;
    if (c.role = 'customer' and v->>'customerId' = c.uid) or (c.role = 'trainer' and v->>'trainerId' = c.uid) then return v; end if;
    if c.role = 'customer' and v->>'status' in ('pending','confirmed') and app_private.customer_knows_trainer(c.uid, v->>'trainerId') then
      -- other people's requests: only the fact that the slot is taken
      return jsonb_strip_nulls(jsonb_build_object('id', v->'id', 'trainerId', v->'trainerId', 'bookingDate', v->'bookingDate',
                                                   'bookingTime', v->'bookingTime', 'status', v->'status', 'sessionMode', v->'sessionMode',
                                                   'private', v->'private'));
    end if;
    return null;
  elsif pfx in ('custpkg','order') then
    if c.role = 'admin'
       or (c.role = 'customer' and v->>'customerId' = c.uid)
       or (c.role = 'trainer' and v->>'trainerId' = c.uid) then return v; end if;
    return null;
  elsif pfx = 'slip' then
    if c.role = 'admin' or (c.role = 'customer' and v->>'customerId' = c.uid) then return v; end if;
    if c.role = 'trainer' and exists (select 1 from public.kv_store where key = 'order:' || coalesce(v->>'orderId','') and value->>'trainerId' = c.uid) then
      return v;
    end if;
    return null;
  elsif pfx = 'tpkg' then
    if c.role = 'admin' or (c.role = 'trainer' and v->>'trainerId' = c.uid) then return v; end if;
    if c.role = 'customer' and v->>'status' = 'active' and app_private.trainer_is_active(v->>'trainerId')
       and app_private.customer_knows_trainer(c.uid, v->>'trainerId') then return v; end if;
    return null;
  elsif pfx = 'trainerpay' then
    if c.role = 'admin' or (c.role = 'trainer' and p_key = 'trainerpay:' || c.uid) then return v; end if;
    if c.role = 'customer' and app_private.trainer_is_active(substr(p_key, 12))
       and app_private.customer_knows_trainer(c.uid, substr(p_key, 12)) then return v; end if;
    return null;
  elsif pfx = 'certimg' then
    if v ? 'appId' and c.role <> 'admin' then return null; end if;      -- pictures of people still waiting for approval
    return v;
  elsif pfx = 'notif' then
    if v->>'userId' = c.uid then return v; end if;
    return null;
  elsif pfx = 'system' then
    if c.role = 'admin' then return v; end if;
    return null;
  end if;
  return null;
end $$;

-- ---------------------------------------------------------------------
-- renaming: copies of a person's name kept inside other rows follow along
-- ---------------------------------------------------------------------
create or replace function app_private.propagate_name(p_role text, p_id text, p_name text) returns void
language plpgsql as $$
declare r record;
begin
  if p_role = 'customer' then
    update public.kv_store set value = value || jsonb_build_object('customerName', p_name)
     where (key like 'booking:%' or key like 'order:%') and value->>'customerId' = p_id and value->>'customerName' is distinct from p_name;
    -- people sharing a pair session see each other's names
    for r in select distinct value->>'trainerId' as tid, value->>'bookingDate' as d, value->>'bookingTime' as tm
               from public.kv_store where key like 'booking:%' and value->>'customerId' = p_id and value->>'sessionMode' = 'duo' loop
      update public.kv_store b set value = b.value || jsonb_build_object('partnerNames',
          (select coalesce(jsonb_agg(x.value->>'customerName' order by x.key), '[]'::jsonb)
             from public.kv_store x
            where x.key like 'booking:%' and x.key <> b.key and x.value->>'trainerId' = r.tid
              and x.value->>'bookingDate' = r.d and x.value->>'bookingTime' = r.tm and x.value->>'sessionMode' = 'duo'))
       where b.key like 'booking:%' and b.value->>'trainerId' = r.tid and b.value->>'bookingDate' = r.d
         and b.value->>'bookingTime' = r.tm and b.value->>'sessionMode' = 'duo';
    end loop;
  elsif p_role = 'trainer' then
    update public.kv_store set value = value || jsonb_build_object('trainerName', p_name)
     where (key like 'booking:%' or key like 'order:%' or key like 'custpkg:%') and value->>'trainerId' = p_id
       and value->>'trainerName' is distinct from p_name;
  end if;
end $$;

-- ---------------------------------------------------------------------
-- WRITE: one function per kind of row. Each returns the value to store.
-- ---------------------------------------------------------------------
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
  if o->>'authProvider' = 'google' then
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

create or replace function app_private.w_trainer(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare nm text; ph text; photo text; lead numeric; cert jsonb; certs jsonb := '[]'::jsonb; iid text; oldids text[];
begin
  if o is null then perform app_private.err(403, 'forbidden'); end if;
  if c.role = 'admin' then
    -- the admin's view has no profile picture, so only the status of what was sent counts; the stored row is kept as it is
    if n->>'status' in ('active','suspended') and app_private.same_except(o, n, array['status','photo']) then
      return o || jsonb_build_object('status', n->>'status');
    end if;
    perform app_private.err(403, 'forbidden');
  end if;
  if c.role <> 'trainer' or o->>'id' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.same_except(o, n, array['name','phone','username','specialty','bio','ready','certs','photo','leadHours','maxPerSlot']) then
    perform app_private.err(403, 'forbidden');
  end if;
  nm := app_private.clean_text(n->>'name', 60);
  if nm = '' then perform app_private.err(400, 'invalid'); end if;
  ph := app_private.clean_text(n->>'phone', 20);
  if ph = '' then ph := coalesce(o->>'phone',''); end if;
  if ph <> '' and not app_private.valid_phone(ph) then perform app_private.err(400, 'invalid'); end if;
  if ph <> coalesce(o->>'phone','') then
    perform pg_advisory_xact_lock(hashtext('phone:' || ph));
    if exists (select 1 from public.kv_store where (key like 'trainer:%' or key like 'trainerApp:%') and key <> p_key
                  and (value->>'phone' = ph or value->>'username' = ph)) then
      perform app_private.err(409, 'phone_used');
    end if;
  end if;
  n := n || jsonb_build_object('name', nm, 'phone', ph,
         'specialty', app_private.clean_text(n->>'specialty', 80), 'bio', app_private.clean_text(n->>'bio', 1000),
         'username', case when o->>'authProvider' = 'google' then o->>'username' else ph end);
  if n ? 'ready' and jsonb_typeof(n->'ready') <> 'boolean' then n := n || jsonb_build_object('ready', true); end if;
  if n ? 'leadHours' then
    begin lead := (n->>'leadHours')::numeric; exception when others then perform app_private.err(400, 'invalid'); end;
    if lead < 0 or lead > 168 then perform app_private.err(400, 'invalid'); end if;
  end if;
  -- how many customers may train in the same time slot (1 = one at a time, 2 = pair, 3 = small group)
  if n ? 'maxPerSlot' then
    if jsonb_typeof(n->'maxPerSlot') <> 'number' or (n->>'maxPerSlot') !~ '^[1-3]$' then perform app_private.err(400, 'invalid'); end if;
    n := n || jsonb_build_object('maxPerSlot', (n->>'maxPerSlot')::int);
  end if;
  if n ? 'photo' then
    photo := n->>'photo';
    if photo is null or not app_private.is_data_url(photo, 64000) then n := n - 'photo'; end if;
  end if;
  -- certificates: text only here; each picture must be one this trainer owns
  if jsonb_typeof(n->'certs') <> 'array' or jsonb_array_length(n->'certs') > 30 then perform app_private.err(400, 'invalid'); end if;
  select coalesce(array_agg(e->>'imgId'), '{}') into oldids from jsonb_array_elements(coalesce(o->'certs','[]'::jsonb)) e where e ? 'imgId';
  for cert in select * from jsonb_array_elements(n->'certs') loop
    cert := jsonb_build_object('name', app_private.clean_text(cert->>'name', 80), 'issuer', app_private.clean_text(cert->>'issuer', 80),
                               'year', app_private.clean_text(cert->>'year', 8)) ||
            case when cert ? 'imgId' then jsonb_build_object('imgId', cert->>'imgId') else '{}'::jsonb end;
    if cert ? 'imgId' then
      iid := cert->>'imgId';
      if not (iid = any(oldids)) and not exists (select 1 from public.kv_store where key = 'certimg:' || iid and value->>'ownerId' = c.uid) then
        perform app_private.err(403, 'forbidden');
      end if;
    end if;
    certs := certs || jsonb_build_array(cert);
  end loop;
  n := n || jsonb_build_object('certs', certs);
  if nm <> coalesce(o->>'name','') then perform app_private.propagate_name('trainer', o->>'id', nm); end if;
  return n;
end $$;

-- someone joined a time that already had people in it: tell each of them (an in-app notice; the phone pop-up follows by itself).
-- The text is written in Thai here; the app shows it in the reader's own language from 'k' and 'p'.
create or replace function app_private.notify_joined(p_trainer text, p_tname text, p_date text, p_time text, p_exclude text, p_n int) returns void
language plpgsql as $$
declare r record; nid text; d date := p_date::date; ds text;
begin
  ds := extract(day from d)::int::text || ' ' ||
        (array['ม.ค.','ก.พ.','มี.ค.','เม.ย.','พ.ค.','มิ.ย.','ก.ค.','ส.ค.','ก.ย.','ต.ค.','พ.ย.','ธ.ค.'])[extract(month from d)::int];
  for r in select value from public.kv_store
            where key like 'booking:%' and value->>'trainerId' = p_trainer and value->>'bookingDate' = p_date
              and value->>'bookingTime' = p_time and value->>'status' in ('pending','confirmed') and value->>'customerId' <> p_exclude loop
    nid := 'notif_' || substr(md5(random()::text || clock_timestamp()::text || (r.value->>'id')), 1, 16);
    insert into public.kv_store(key, value, updated_at) values ('notif:' || nid, jsonb_build_object(
      'id', nid, 'userId', r.value->>'customerId', 'title', 'การจองของฉัน',
      'message', 'มีคนเข้าร่วมรอบเทรนของคุณกับ ' || coalesce(p_tname, '') || ' วันที่ ' || ds || ' เวลา ' || p_time || ' ตอนนี้ ' || p_n || ' คน',
      'isRead', false, 'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
      'bookingId', r.value->>'id', 'k', 'notif_joined',
      'p', jsonb_build_object('trainer', coalesce(p_tname, ''), 'date', p_date, 'time', p_time, 'n', p_n)), now());
  end loop;
end $$;

create or replace function app_private.w_booking(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare
  t jsonb; pkg jsonb; cu jsonb; d date; tm text; start_ts timestamptz; lead numeric; tid text; open_n int; pid text;
  mode text; pn jsonb; other_conf int; from_s text; to_s text; cap int; at_n int; has_private boolean; priv boolean;
begin
  if o is null then
    if c.role <> 'customer' or n->>'customerId' is distinct from c.uid then perform app_private.err(403, 'forbidden'); end if;
    if p_key !~ '^booking:bk_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
    tid := coalesce(n->>'trainerId', '');
    select value into t from public.kv_store where key = 'trainer:' || tid;
    if t is null or t->>'status' <> 'active' then perform app_private.err(400, 'trainer_unavailable'); end if;
    pid := coalesce(n->>'packageInstanceId', '');
    select value into pkg from public.kv_store where key = 'custpkg:' || pid;
    if pkg is null or pkg->>'customerId' <> c.uid or pkg->>'trainerId' is distinct from tid
       or pkg->>'status' <> 'active' or coalesce((pkg->>'remainingSessions')::int, 0) <= 0
       or coalesce(pkg->>'expiryDate', '9999-12-31') < app_private.today()::text then
      perform app_private.err(400, 'no_package');
    end if;
    tm := coalesce(n->>'bookingTime', '');
    if tm !~ '^([01][0-9]|2[0-3]):[0-5][0-9]$' or coalesce(n->>'bookingDate','') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' then
      perform app_private.err(400, 'invalid');
    end if;
    begin d := (n->>'bookingDate')::date; exception when others then perform app_private.err(400, 'invalid'); end;
    if d < app_private.today() or d > app_private.today() + 90 then perform app_private.err(400, 'invalid_date'); end if;
    -- a session cannot be booked for a day after the package runs out
    if coalesce(pkg->>'expiryDate', '9999-12-31') < n->>'bookingDate' then perform app_private.err(400, 'no_package'); end if;
    start_ts := ((n->>'bookingDate') || ' ' || tm)::timestamp at time zone 'Asia/Bangkok';
    lead := case when coalesce(t->>'leadHours','') ~ '^[0-9]+(\.[0-9]+)?$' then (t->>'leadHours')::numeric else 1 end;
    if start_ts - now() < make_interval(secs => lead * 3600) then perform app_private.err(409, 'too_soon'); end if;

    perform pg_advisory_xact_lock(hashtext('slot:' || tid || (n->>'bookingDate') || tm));
    if exists (select 1 from public.kv_store where key like 'booking:%' and value->>'trainerId' = tid and value->>'bookingDate' = n->>'bookingDate'
                  and value->>'bookingTime' = tm and value->>'status' in ('pending','confirmed') and value->>'customerId' = c.uid) then
      perform app_private.err(409, 'already_mine');
    end if;
    -- how many people may train at the same time: the trainer's own setting (1 = one customer per time, as it always was;
    -- 2 = pair; 3 = small group). A booking goes onto the trainer's schedule straight away; whoever books while there is still room joins in.
    cap := case when coalesce(t->>'maxPerSlot', '') ~ '^[1-3]$' then (t->>'maxPerSlot')::int else 1 end;
    select count(*), coalesce(bool_or(coalesce((value->>'private')::boolean, false)), false) into at_n, has_private
      from public.kv_store where key like 'booking:%' and value->>'trainerId' = tid and value->>'bookingDate' = n->>'bookingDate'
       and value->>'bookingTime' = tm and value->>'status' in ('pending','confirmed');
    -- full, or the first person asked to train alone: nobody else gets in
    if at_n >= cap or has_private then perform app_private.err(409, 'locked'); end if;
    -- "I want this time to myself" only works for a time nobody has booked yet, and only where the trainer takes more than one person
    priv := false;
    if coalesce(n->>'private', '') = 'true' and cap >= 2 then
      if at_n > 0 then perform app_private.err(409, 'not_alone'); end if;
      priv := true;
    end if;

    select count(*) into open_n from public.kv_store
     where key like 'booking:%' and value->>'packageInstanceId' = pid and value->>'status' in ('pending','confirmed');
    if open_n >= (pkg->>'remainingSessions')::int then perform app_private.err(400, 'no_package'); end if;
    if (select count(*) from public.kv_store where key like 'booking:%' and value->>'customerId' = c.uid
           and value->>'status' in ('pending','confirmed') and value->>'bookingDate' >= app_private.today()::text) >= 30 then
      perform app_private.err(429, 'too_many_open');
    end if;
    cu := (select value from public.kv_store where key = c.ukey);
    -- the people already booked at this time are told that someone joined (they cannot see who: customers never see each other)
    if at_n > 0 then perform app_private.notify_joined(tid, t->>'name', n->>'bookingDate', tm, c.uid, at_n + 1); end if;
    return jsonb_build_object('id', substr(p_key, 9), 'customerId', c.uid, 'customerName', cu->>'name', 'trainerId', tid,
        'trainerName', t->>'name', 'packageInstanceId', pid, 'bookingDate', n->>'bookingDate', 'bookingTime', tm,
        'status', 'confirmed', 'sessionMode', 'solo', 'partnerNames', '[]'::jsonb, 'private', priv,
        'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'), 'completedAt', null);
  end if;

  if n = o then return o; end if;
  if c.role = 'customer' and o->>'customerId' = c.uid then
    -- the customer may only withdraw a request that has not been done
    if app_private.same_except(o, n, array['status']) and n->>'status' = 'cancelled' and o->>'status' in ('pending','confirmed') then return n; end if;
    perform app_private.err(403, 'forbidden');
  elsif c.role = 'trainer' and o->>'trainerId' = c.uid then
    if not app_private.same_except(o, n, array['status','sessionMode','partnerNames','completedAt']) then perform app_private.err(403, 'forbidden'); end if;
    from_s := o->>'status'; to_s := n->>'status';
    if not ((from_s = 'pending'   and to_s in ('pending','confirmed','rejected','cancelled'))
         or (from_s = 'confirmed' and to_s in ('confirmed','completed','no_show','cancelled'))) then
      perform app_private.err(409, 'bad_transition');
    end if;
    mode := n->>'sessionMode';
    if mode is not null and mode not in ('solo','duo') then perform app_private.err(400, 'invalid'); end if;
    pn := coalesce(n->'partnerNames', '[]'::jsonb);
    if jsonb_typeof(pn) <> 'array' or jsonb_array_length(pn) > 2 then perform app_private.err(400, 'invalid'); end if;
    n := n || jsonb_build_object('partnerNames', (select coalesce(jsonb_agg(left(e, 60)), '[]'::jsonb) from jsonb_array_elements_text(pn) e));
    if to_s = 'confirmed' and from_s = 'pending' then
      perform pg_advisory_xact_lock(hashtext('slot:' || (o->>'trainerId') || (o->>'bookingDate') || (o->>'bookingTime')));
      select count(*) into other_conf from public.kv_store where key like 'booking:%' and key <> p_key
         and value->>'trainerId' = o->>'trainerId' and value->>'bookingDate' = o->>'bookingDate'
         and value->>'bookingTime' = o->>'bookingTime' and value->>'status' = 'confirmed';
      select case when coalesce(value->>'maxPerSlot', '') ~ '^[1-3]$' then (value->>'maxPerSlot')::int else 1 end into cap
        from public.kv_store where key = 'trainer:' || (o->>'trainerId');
      if other_conf >= greatest(coalesce(cap, 1), case when mode = 'duo' then 2 else 1 end) then perform app_private.err(409, 'locked'); end if;
    end if;
    if to_s in ('completed','no_show') and from_s = 'confirmed' then
      n := n || jsonb_build_object('completedAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    end if;
    return n;
  end if;
  perform app_private.err(403, 'forbidden');
  return null;
end $$;

create or replace function app_private.w_order(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare oid text := substr(p_key, 7); tp jsonb; tr jsonb; pay jsonb; cu jsonb; inst boolean; now_s text :=
          to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
begin
  if o is null then
    if c.role <> 'customer' or n->>'customerId' is distinct from c.uid then perform app_private.err(403, 'forbidden'); end if;
    if p_key !~ '^order:ord_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
    select value into tp from public.kv_store where key = 'tpkg:' || coalesce(n->>'tpkgId', '');
    if tp is null or tp->>'status' <> 'active' or coalesce((tp->>'price')::numeric, 0) <= 0 then perform app_private.err(400, 'pay_not_found'); end if;
    select value into tr from public.kv_store where key = 'trainer:' || (tp->>'trainerId');
    if tr is null or tr->>'status' <> 'active' then perform app_private.err(400, 'pay_not_found'); end if;
    select value into pay from public.kv_store where key = 'trainerpay:' || (tp->>'trainerId');
    if pay is null or coalesce(pay->>'qr', '') = '' then perform app_private.err(400, 'pay_no_qr'); end if;
    if not exists (select 1 from public.kv_store where key = 'slip:' || oid and value->>'customerId' = c.uid) then perform app_private.err(400, 'pay_need_slip'); end if;
    if exists (select 1 from public.kv_store where key like 'order:%' and value->>'customerId' = c.uid and value->>'tpkgId' = tp->>'id' and value->>'status' = 'pending') then
      perform app_private.err(409, 'pay_dup');
    end if;
    if (select count(*) from public.kv_store where key like 'order:%' and value->>'customerId' = c.uid and value->>'status' = 'pending') >= 5 then
      perform app_private.err(429, 'too_many_open');
    end if;
    inst := coalesce(pay->>'instantCredit', 'true') <> 'false';
    cu := (select value from public.kv_store where key = c.ukey);
    return jsonb_build_object('id', oid, 'customerId', c.uid, 'customerName', cu->>'name', 'trainerId', tr->>'id', 'trainerName', tr->>'name',
        'tpkgId', tp->>'id', 'packageName', tp->>'name', 'sessions', (tp->>'sessions')::int, 'price', (tp->>'price')::numeric,
        'expirationDays', coalesce((tp->>'expirationDays')::int, 90), 'instant', inst,
        'custpkgId', case when inst then to_jsonb('co_' || oid) else null end, 'status', 'pending', 'createdAt', now_s);
  end if;
  if n = o then return o; end if;
  if o->>'status' <> 'pending' then perform app_private.err(409, 'bad_transition'); end if;
  if c.role = 'customer' and o->>'customerId' = c.uid then
    if n->>'status' = 'cancelled' and app_private.same_except(o, n, array['status','decidedAt']) then
      return n || jsonb_build_object('decidedAt', now_s);
    end if;
  elsif c.role = 'trainer' and o->>'trainerId' = c.uid then
    if n->>'status' in ('approved','rejected') and app_private.same_except(o, n, array['status','decidedAt','custpkgId']) then
      return (n - 'custpkgId') || jsonb_build_object('decidedAt', now_s)
             || case when n->>'status' = 'approved' then jsonb_build_object('custpkgId', 'co_' || oid)
                     else jsonb_build_object('custpkgId', o->'custpkgId') end;
    end if;
  end if;
  perform app_private.err(403, 'forbidden');
  return null;
end $$;

create or replace function app_private.w_custpkg(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare cid text := substr(p_key, 9); oid text; ord jsonb; v jsonb; prov boolean; used int; rem int; tot int;
begin
  if o is null then
    -- a package only ever comes from an order
    if cid !~ '^co_ord_[a-z0-9]{6,30}$' then perform app_private.err(403, 'forbidden'); end if;
    oid := substr(cid, 4);
    select value into ord from public.kv_store where key = 'order:' || oid;
    if ord is null then perform app_private.err(403, 'forbidden'); end if;
    if c.role = 'customer' and ord->>'customerId' = c.uid and (ord->>'instant')::boolean and ord->>'status' = 'pending' and ord->>'custpkgId' = cid then
      prov := true;
    elsif c.role = 'trainer' and ord->>'trainerId' = c.uid and ord->>'status' in ('pending','approved') then
      prov := false;
    else
      perform app_private.err(403, 'forbidden');
    end if;
    v := jsonb_build_object('id', cid, 'customerId', ord->>'customerId', 'trainerId', ord->>'trainerId', 'trainerName', ord->>'trainerName',
        'orderId', oid, 'packageId', ord->>'tpkgId', 'packageName', ord->>'packageName', 'totalSessions', (ord->>'sessions')::int,
        'usedSessions', 0, 'remainingSessions', (ord->>'sessions')::int, 'pricePaid', (ord->>'price')::numeric,
        'startDate', app_private.today()::text, 'expiryDate', (app_private.today() + coalesce((ord->>'expirationDays')::int, 90))::text, 'status', 'active');
    if prov then v := v || jsonb_build_object('provisional', true); end if;
    return v;
  end if;
  if n = o then return o; end if;
  if c.role = 'trainer' and o->>'trainerId' = c.uid then
    if not app_private.same_except(o, n, array['usedSessions','remainingSessions','status','provisional','cancelledAt']) then perform app_private.err(403, 'forbidden'); end if;
    used := (n->>'usedSessions')::int; rem := (n->>'remainingSessions')::int; tot := (o->>'totalSessions')::int;
    if used is null or rem is null or used < 0 or rem < 0 or used + rem <> tot then perform app_private.err(400, 'invalid'); end if;
    if n->>'status' not in ('active','used_up','cancelled','expired') then perform app_private.err(400, 'invalid'); end if;
    if o->>'status' = 'cancelled' and n->>'status' <> 'cancelled' then perform app_private.err(409, 'bad_transition'); end if;
    if n ? 'provisional' and jsonb_typeof(n->'provisional') <> 'boolean' then perform app_private.err(400, 'invalid'); end if;
    return n;
  elsif c.role = 'customer' and o->>'customerId' = c.uid then
    -- withdrawing an order that is not yet confirmed cancels its provisional package
    if coalesce((o->>'provisional')::boolean, false) and o->>'status' = 'active'
       and n->>'status' = 'cancelled' and coalesce((n->>'provisional')::boolean, false) = false
       and app_private.same_except(o, n, array['status','provisional','cancelledAt'])
       and exists (select 1 from public.kv_store where key = 'order:' || (o->>'orderId') and value->>'status' = 'cancelled') then
      return n;
    end if;
  end if;
  perform app_private.err(403, 'forbidden');
  return null;
end $$;

create or replace function app_private.w_slip(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare sid text := substr(p_key, 6); ord jsonb;
begin
  if c.role <> 'customer' then perform app_private.err(403, 'forbidden'); end if;
  if p_key !~ '^slip:ord_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
  if o is not null and o->>'customerId' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  select value into ord from public.kv_store where key = 'order:' || sid;
  if ord is not null and (ord->>'customerId' <> c.uid or ord->>'status' <> 'pending') then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.is_data_url(n->>'image', 300000) then perform app_private.err(400, 'invalid_image'); end if;
  if o is null and (select count(*) from public.kv_store where key like 'slip:%' and value->>'customerId' = c.uid) >= 8 then
    perform app_private.err(429, 'too_many_open');
  end if;
  return jsonb_build_object('orderId', sid, 'image', n->>'image', 'customerId', c.uid,
                            'createdAt', coalesce(o->>'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
end $$;

create or replace function app_private.w_tpkg(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare nm text; s int; ex int; pr numeric; st text;
begin
  if c.role <> 'trainer' then perform app_private.err(403, 'forbidden'); end if;
  if p_key !~ '^tpkg:tp_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
  if o is not null and o->>'trainerId' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  nm := app_private.clean_text(n->>'name', 40);
  if nm = '' then perform app_private.err(400, 'invalid'); end if;
  begin
    s := floor((n->>'sessions')::numeric)::int; ex := floor((n->>'expirationDays')::numeric)::int; pr := round((n->>'price')::numeric, 2);
  exception when others then perform app_private.err(400, 'invalid'); end;
  if s not between 1 and 200 or ex not between 1 and 730 or pr < 0 or pr > 1000000 then perform app_private.err(400, 'invalid'); end if;
  st := n->>'status';
  if st not in ('active','hidden') or (st = 'active' and pr <= 0) then perform app_private.err(400, 'invalid'); end if;
  if o is null and (select count(*) from public.kv_store where key like 'tpkg:%' and value->>'trainerId' = c.uid) >= 30 then
    perform app_private.err(429, 'too_many_open');
  end if;
  return jsonb_build_object('id', substr(p_key, 6), 'trainerId', c.uid, 'name', nm, 'sessions', s, 'price', pr, 'expirationDays', ex, 'status', st,
                            'createdAt', coalesce(o->>'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
end $$;

create or replace function app_private.w_trainerpay(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare qr text := coalesce(n->>'qr', '');
begin
  if c.role <> 'trainer' or p_key <> 'trainerpay:' || c.uid then perform app_private.err(403, 'forbidden'); end if;
  if qr <> '' and not app_private.is_data_url(qr, 430000) then perform app_private.err(400, 'invalid_image'); end if;
  return jsonb_build_object('trainerId', c.uid, 'qr', qr,
      'instantCredit', case when n ? 'instantCredit' then coalesce((n->>'instantCredit')::boolean, true)
                            when o ? 'instantCredit' then (o->>'instantCredit')::boolean else true end,
      'updatedAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
end $$;

create or replace function app_private.w_certimg(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
begin
  if c.role <> 'trainer' then perform app_private.err(403, 'forbidden'); end if;
  if p_key !~ '^certimg:ci_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
  if o is not null and o->>'ownerId' is distinct from c.uid then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.is_data_url(n->>'data', 480000) then perform app_private.err(400, 'invalid_image'); end if;
  if o is null and (select count(*) from public.kv_store where key like 'certimg:%' and value->>'ownerId' = c.uid) >= 40 then
    perform app_private.err(429, 'too_many_open');
  end if;
  return jsonb_build_object('data', n->>'data', 'ownerId', c.uid,
                            'createdAt', coalesce(o->>'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')));
end $$;

create or replace function app_private.w_notif(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare rcpt text; ok boolean := false;
begin
  if o is null then
    if p_key !~ '^notif:notif_[a-z0-9]{6,30}$' then perform app_private.err(400, 'invalid'); end if;
    rcpt := coalesce(n->>'userId', '');
    if rcpt = '' or length(rcpt) > 60 then perform app_private.err(400, 'invalid'); end if;
    if c.role = 'admin' or rcpt = c.uid then ok := true;
    elsif c.role = 'customer' then ok := app_private.rel_trainer_customer(rcpt, c.uid);
    elsif c.role = 'trainer' then ok := app_private.rel_trainer_customer(c.uid, rcpt);
    end if;
    if not ok then perform app_private.err(403, 'forbidden'); end if;
    perform app_private.rate_hit('n:' || c.ukey, 3600, 300);
    -- keep each person's inbox from growing without limit
    delete from public.kv_store where key in (
      select key from public.kv_store where key like 'notif:%' and value->>'userId' = rcpt order by key desc offset 400);
    return jsonb_build_object('id', substr(p_key, 7), 'userId', rcpt, 'title', app_private.clean_text(n->>'title', 120),
        'message', app_private.clean_text(n->>'message', 400), 'isRead', false,
        'createdAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
        'bookingId', case when coalesce(n->>'bookingId','') = '' then null else to_jsonb(left(n->>'bookingId', 60)) end);
  end if;
  if o->>'userId' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  if n = o then return o; end if;
  if app_private.same_except(o, n, array['isRead']) and n->>'isRead' = 'true' then return n; end if;
  perform app_private.err(403, 'forbidden');
  return null;
end $$;

-- ---------------------------------------------------------------------
-- DELETE
-- ---------------------------------------------------------------------
create or replace function app_private.check_delete(c app_private.ctx_t, p_key text, o jsonb) returns void
language plpgsql as $$
declare pfx text := split_part(p_key, ':', 1); ord jsonb;
begin
  if o is null then return; end if;
  if pfx = 'tpkg' and c.role = 'trainer' and o->>'trainerId' = c.uid then return; end if;
  if pfx = 'certimg' and ((c.role = 'trainer' and o->>'ownerId' = c.uid) or c.role = 'admin') then return; end if;
  if pfx = 'notif' and o->>'userId' = c.uid then return; end if;
  if pfx = 'slip' then
    select value into ord from public.kv_store where key = 'order:' || (o->>'orderId');
    if c.role = 'admin' or (c.role = 'customer' and o->>'customerId' = c.uid)
       or (c.role = 'trainer' and ord is not null and ord->>'trainerId' = c.uid) then return; end if;
  end if;
  -- a customer taking back an order that was only just made (the send failed half way)
  if pfx = 'order' and c.role = 'customer' and o->>'customerId' = c.uid and o->>'status' = 'pending' then return; end if;
  if pfx = 'custpkg' and c.role = 'customer' and o->>'customerId' = c.uid and coalesce((o->>'provisional')::boolean, false)
     and (o->>'usedSessions')::int = 0 then return; end if;
  perform app_private.err(403, 'forbidden');
end $$;

-- ---------------------------------------------------------------------
-- the four doors the browser uses
-- ---------------------------------------------------------------------
create or replace function public.app_get(p_token text, p_key text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); v jsonb;
begin
  if p_key is null or p_key !~ '^[A-Za-z]{2,12}:[A-Za-z0-9_.@-]{1,80}$' then return null; end if;
  select value into v from public.kv_store where key = p_key;
  return app_private.read_view(c, p_key, v);
end $$;

-- one page of rows under a prefix. next = where to continue (null when finished)
create or replace function public.app_list(p_token text, p_prefix text, p_after text default null, p_limit int default 300) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); lim int := least(greatest(coalesce(p_limit, 300), 1), 500);
        r record; rows jsonb := '[]'::jsonb; view jsonb; scanned int := 0; last_k text;
begin
  if p_prefix is null or p_prefix !~ '^[A-Za-z]{2,12}:$' then perform app_private.err(400, 'invalid'); end if;
  if p_prefix not in ('admin:','customer:','trainer:','trainerApp:','booking:','custpkg:','order:','tpkg:','trainerpay:','notif:','system:','certimg:','slip:') then
    perform app_private.err(400, 'invalid');
  end if;
  -- pictures are fetched one at a time by id; only the admin may list them
  if p_prefix in ('certimg:','slip:') and c.role <> 'admin' then return jsonb_build_object('rows', '[]'::jsonb, 'next', null); end if;
  for r in select key, value from public.kv_store
            where key like p_prefix || '%' and key > coalesce(p_after, '') order by key limit lim loop
    scanned := scanned + 1; last_k := r.key;
    view := app_private.read_view(c, r.key, r.value);
    if view is not null then rows := rows || jsonb_build_array(jsonb_build_object('k', r.key, 'v', view)); end if;
  end loop;
  return jsonb_build_object('rows', rows, 'next', case when scanned = lim then last_k else null end);
end $$;

create or replace function public.app_set(p_token text, p_key text, p_value jsonb) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); o jsonb; n jsonb; pfx text;
begin
  if p_key is null or p_key !~ '^[A-Za-z]{2,12}:[A-Za-z0-9_.@-]{1,80}$' then perform app_private.err(400, 'invalid'); end if;
  if p_value is null or jsonb_typeof(p_value) <> 'object' or length(p_value::text) > 700000 then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('w:' || c.ukey, 60, 300);
  perform pg_advisory_xact_lock(hashtextextended(p_key, 0));
  select value into o from public.kv_store where key = p_key;
  pfx := split_part(p_key, ':', 1);
  n := case pfx
    when 'customer'   then app_private.w_customer(c, p_key, o, p_value)
    when 'trainer'    then app_private.w_trainer(c, p_key, o, p_value)
    when 'booking'    then app_private.w_booking(c, p_key, o, p_value)
    when 'order'      then app_private.w_order(c, p_key, o, p_value)
    when 'custpkg'    then app_private.w_custpkg(c, p_key, o, p_value)
    when 'slip'       then app_private.w_slip(c, p_key, o, p_value)
    when 'tpkg'       then app_private.w_tpkg(c, p_key, o, p_value)
    when 'trainerpay' then app_private.w_trainerpay(c, p_key, o, p_value)
    when 'certimg'    then app_private.w_certimg(c, p_key, o, p_value)
    when 'notif'      then app_private.w_notif(c, p_key, o, p_value)
    else null end;
  if n is null then perform app_private.err(403, 'forbidden'); end if;
  insert into public.kv_store(key, value, updated_at) values (p_key, n, now())
  on conflict (key) do update set value = excluded.value, updated_at = now();
  return jsonb_build_object('ok', true, 'value', app_private.read_view(c, p_key, n));
end $$;

create or replace function public.app_del(p_token text, p_key text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); o jsonb;
begin
  if p_key is null or p_key !~ '^[A-Za-z]{2,12}:[A-Za-z0-9_.@-]{1,80}$' then perform app_private.err(400, 'invalid'); end if;
  perform app_private.rate_hit('w:' || c.ukey, 60, 300);
  perform pg_advisory_xact_lock(hashtextextended(p_key, 0));
  select value into o from public.kv_store where key = p_key;
  perform app_private.check_delete(c, p_key, o);
  delete from public.kv_store where key = p_key;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------------
-- a customer types a trainer's code (the only way to find a trainer); misses are counted and slowed down
-- ---------------------------------------------------------------------
create or replace function public.app_find_trainer(p_token text, p_code text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token); code text; b text; bi text; lk int; k text; v jsonb;
begin
  if c.role <> 'customer' then perform app_private.err(403, 'forbidden'); end if;
  code := upper(regexp_replace(coalesce(p_code, ''), '[^A-Za-z0-9]', '', 'g'));
  if length(code) < 1 or length(code) > 8 then return jsonb_build_object('ok', false, 'reason', 'notfound'); end if;
  b := 'f:' || c.ukey; bi := 'fi:' || app_private.client_ip();
  lk := greatest(app_private.lock_left(b), app_private.lock_left(bi));
  if lk > 0 then return jsonb_build_object('ok', false, 'reason', 'locked', 'retry', lk); end if;
  select key, value into k, v from public.kv_store where key like 'trainer:%' and value->>'code' = code and value->>'status' = 'active' limit 1;
  if k is null then
    perform app_private.lock_fail(b, 8, 600, 600);
    perform app_private.lock_fail(bi, 60, 900, 600);
    return jsonb_build_object('ok', false, 'reason', 'notfound');
  end if;
  return jsonb_build_object('ok', true, 'trainer', app_private.trainer_public(v));
end $$;

-- the numbers on the admin dashboard (counts only; no rows travel)
create or replace function public.app_admin_stats(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token);
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('stats:' || c.ukey, 60, 60);
  return jsonb_build_object('ok', true,
    'trainers',  (select count(*) from public.kv_store where key like 'trainer:%'),
    'customers', (select count(*) from public.kv_store where key like 'customer:%'),
    'apps',      (select count(*) from public.kv_store where key like 'trainerApp:%'),
    'appsPending', (select count(*) from public.kv_store where key like 'trainerApp:%' and value->>'status' = 'pending'),
    'packages',  (select count(*) from public.kv_store where key like 'tpkg:%' and value->>'status' = 'active'
                    and (value->>'price') ~ '^[0-9]+(\.[0-9]+)?$' and (value->>'price')::numeric > 0),
    'bookings',  (select count(*) from public.kv_store where key like 'booking:%'),
    'activePkgs', (select count(*) from public.kv_store where key like 'custpkg:%' and value->>'status' = 'active'));
end $$;

-- the admin's "clean up now" button
create or replace function public.app_admin_maintain(p_token text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare c app_private.ctx_t := app_private.ctx(p_token);
begin
  if c.role <> 'admin' then perform app_private.err(403, 'forbidden'); end if;
  perform app_private.rate_hit('maint:' || c.ukey, 600, 5);
  perform app_private.maintenance();
  perform app_private.audit(c.ukey, 'maintenance', null, true, null);
  return jsonb_build_object('ok', true);
end $$;
-- =====================================================================
-- part 4: pop-up notifications on phones (Web Push)
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
-- part 4: housekeeping (runs by itself, at most once a day, when someone signs in)
-- =====================================================================
create or replace function app_private.iso_ok(p text) returns boolean
language sql immutable as $$ select p is not null and p ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z$' $$;

create or replace function app_private.maintenance() returns void
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare r record; cp jsonb;
begin
  -- finished bookings after 90 days, read notifications after 30
  delete from public.kv_store where key like 'booking:%' and value->>'status' in ('completed','no_show','rejected','cancelled')
     and app_private.iso_ok(coalesce(value->>'completedAt', value->>'createdAt'))
     and coalesce(value->>'completedAt', value->>'createdAt')::timestamptz < now() - interval '90 days';
  delete from public.kv_store where key like 'notif:%' and value->>'isRead' = 'true'
     and app_private.iso_ok(value->>'createdAt') and (value->>'createdAt')::timestamptz < now() - interval '30 days';
  -- orders nobody answered for a month: cancel them, void the provisional package and its open bookings, drop the slip
  for r in select key, value from public.kv_store where key like 'order:%' and value->>'status' = 'pending'
              and app_private.iso_ok(value->>'createdAt') and (value->>'createdAt')::timestamptz < now() - interval '30 days' loop
    update public.kv_store set value = value || jsonb_build_object('status','cancelled','decidedAt', to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) where key = r.key;
    select value into cp from public.kv_store where key = 'custpkg:' || coalesce(r.value->>'custpkgId', 'co_' || (r.value->>'id'));
    if cp is not null and coalesce((cp->>'provisional')::boolean, false) then
      update public.kv_store set value = value || jsonb_build_object('status','cancelled','provisional',false,'cancelledAt', to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
       where key = 'custpkg:' || (cp->>'id');
      update public.kv_store set value = value || jsonb_build_object('status','cancelled')
       where key like 'booking:%' and value->>'packageInstanceId' = cp->>'id' and value->>'status' in ('pending','confirmed');
    end if;
    delete from public.kv_store where key = 'slip:' || (r.value->>'id');
  end loop;
  for r in select key, value from public.kv_store where key like 'order:%' and value->>'status' <> 'pending'
              and app_private.iso_ok(coalesce(value->>'decidedAt', value->>'createdAt'))
              and coalesce(value->>'decidedAt', value->>'createdAt')::timestamptz < now() - interval '90 days' loop
    delete from public.kv_store where key = r.key or key = 'slip:' || (r.value->>'id');
  end loop;
  -- leftovers: slips with no pending order, pictures of applications that no longer exist
  delete from public.kv_store s where s.key like 'slip:%' and app_private.iso_ok(s.value->>'createdAt')
     and (s.value->>'createdAt')::timestamptz < now() - interval '1 day'
     and not exists (select 1 from public.kv_store o where o.key = 'order:' || (s.value->>'orderId') and o.value->>'status' = 'pending');
  delete from public.kv_store i where i.key like 'certimg:%' and i.value ? 'appId' and app_private.iso_ok(i.value->>'createdAt')
     and (i.value->>'createdAt')::timestamptz < now() - interval '1 day'
     and not exists (select 1 from public.kv_store a where a.key = 'trainerApp:' || (i.value->>'appId'));
  -- the security tables
  delete from app_private.session where expires_at <= now();
  delete from app_private.ticket where expires_at <= now();
  delete from app_private.rate where win < floor(extract(epoch from now()) / 3600)::bigint - 48 and win < 100000000;
  delete from app_private.fail where (locked_until is null or locked_until < now()) and first_at < now() - interval '1 day';
  delete from app_private.audit where at < now() - interval '180 days';
  insert into public.kv_store(key, value) values ('system:maintenance', jsonb_build_object('ts', to_char(now() at time zone 'utc','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')))
  on conflict (key) do update set value = excluded.value, updated_at = now();
end $$;

create or replace function app_private.maintenance_if_due() returns void
language plpgsql security definer set search_path = pg_catalog, public, app_private, extensions as $$
declare last timestamptz;
begin
  if not pg_try_advisory_xact_lock(727272) then return; end if;
  select (value->>'ts')::timestamptz into last from public.kv_store where key = 'system:maintenance';
  if last is null or last < now() - interval '1 day' then perform app_private.maintenance(); end if;
exception when others then
  null;   -- housekeeping must never stop someone from signing in
end $$;

-- a harmless call for the scheduled "keep awake" check: it touches the database and returns nothing private
create or replace function public.app_ping() returns jsonb
language sql security definer set search_path = pg_catalog, public, app_private, extensions as $$
  select jsonb_build_object('ok', exists (select 1 from public.kv_store limit 1) or true)
$$;
-- =====================================================================
-- part 5: move the existing accounts onto the new login system
-- =====================================================================
-- Passwords that are sitting in the data as plain text are turned into bcrypt hashes.
insert into app_private.cred(ukey, pw_hash)
select k.key, extensions.crypt(k.value->>'password', extensions.gen_salt('bf', 10))
  from public.kv_store k
 where (k.key like 'trainer:%' or k.key like 'customer:%' or k.key like 'trainerApp:%')
   and coalesce(k.value->>'password','') <> ''
   and not exists (select 1 from app_private.cred c where c.ukey = k.key);

-- The old admin password was visible in the website's source, so it is retired right now:
-- it is removed from the data and the admin cannot sign in until a new one is set (see the README).
update public.kv_store set value = value - 'password' where key = 'admin:admin';
insert into app_private.cred(ukey, pw_hash)
values ('admin:admin', extensions.crypt(app_private.rand_hex(32), extensions.gen_salt('bf', 10)))
on conflict (ukey) do update set pw_hash = excluded.pw_hash, updated_at = now();
delete from app_private.session where ukey = 'admin:admin';
-- =====================================================================
-- part 6: who may call what
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

-- make the API pick up the new functions straight away
notify pgrst, 'reload schema';
