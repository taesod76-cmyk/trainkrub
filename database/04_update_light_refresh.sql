-- =====================================================================
-- TRAINKRUB update (round 13): lighter refresh.
-- For a database that already ran 01_install.sql, 02_lockdown.sql and 03_update_trainer_signup.sql.
-- Safe to run more than once. Nothing here touches your data.
--  * the admin's lists no longer carry profile pictures (the admin pages never show them)
--  * the admin can still suspend / re-activate a user, and the stored picture is kept
--  * one small call gives the numbers on the admin dashboard
-- =====================================================================

create or replace function app_private.read_view(c app_private.ctx_t, p_key text, v jsonb) returns jsonb
language plpgsql stable as $$
declare pfx text := split_part(p_key, ':', 1);
begin
  if v is null then return null; end if;
  if pfx = 'admin' then
    if c.role = 'admin' then return v - 'password'; end if;
    return null;
  elsif pfx = 'customer' then
    if c.role = 'admin' then return v - 'password' - 'photo'; end if;
    if c.role = 'customer' and v->>'id' = c.uid then return v - 'password'; end if;
    if c.role = 'trainer' and app_private.rel_trainer_customer(c.uid, v->>'id') then
      return jsonb_strip_nulls(jsonb_build_object('id', v->'id', 'name', v->'name', 'phone', v->'phone', 'photo', v->'photo',
                                                   'status', v->'status', 'role', v->'role'));
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
                                                   'bookingTime', v->'bookingTime', 'status', v->'status', 'sessionMode', v->'sessionMode'));
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

create or replace function app_private.w_customer(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare nm text; ph text; photo text; arr jsonb; x jsonb;
begin
  if o is null then perform app_private.err(403, 'forbidden'); end if;
  if c.role = 'admin' then
    -- the admin's view has no profile picture, so only the status of what was sent counts; the stored row is kept as it is
    if n->>'status' in ('active','suspended') and app_private.same_except(o, n, array['status','photo']) then
      return o || jsonb_build_object('status', n->>'status');
    end if;
    perform app_private.err(403, 'forbidden');
  end if;
  if c.role <> 'customer' or o->>'id' <> c.uid then perform app_private.err(403, 'forbidden'); end if;
  if not app_private.same_except(o, n, array['name','phone','username','photo','pinnedTrainerIds','myTrainerIds']) then
    perform app_private.err(403, 'forbidden');
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
  if not app_private.same_except(o, n, array['name','phone','username','specialty','bio','ready','certs','photo','leadHours']) then
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
              'app_find_trainer','app_admin_maintain','app_admin_stats','app_ping','app_finish_apply') loop
    execute format('grant execute on function %s to anon, authenticated', f.sig);
  end loop;
end $$;


-- make the API pick up the new function straight away
notify pgrst, 'reload schema';
