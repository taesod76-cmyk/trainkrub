-- =====================================================================
-- TRAINKRUB update (round 12): trainers who apply are accepted at once.
-- For a database that already ran 01_install.sql and 02_lockdown.sql.
-- Safe to run more than once. Nothing here touches your data.
-- =====================================================================

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

-- =====================================================================
-- who may call what (re-applied so the new function gets the same rules)
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
              'app_find_trainer','app_admin_maintain','app_ping','app_finish_apply') loop
    execute format('grant execute on function %s to anon, authenticated', f.sig);
  end loop;
end $$;


-- make the API pick up the new function straight away
notify pgrst, 'reload schema';
