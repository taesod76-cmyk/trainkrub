-- =====================================================================
-- TRAINKRUB update (round 17): a booking needs a package of THAT trainer + health information the trainer can see.
-- For a database that already ran 01_install.sql and 02_lockdown.sql (and the updates 03 to 06).
-- Safe to run more than once. Run it BEFORE publishing the website version that goes with it.
--  * a customer can only book a trainer whose package they hold (an old package that names no trainer no longer works with everyone)
--  * a session cannot be booked for a day after the package runs out
--  * a customer can save their health information (conditions, injuries, medicines/allergies, goal, emergency contact, age, weight, height)
--    together with their agreement; a trainer sees it only while they really work together (a package or a booking that stands);
--    the admin never sees it
-- It only replaces server functions; no stored data is changed.
-- =====================================================================

create or replace function app_private.trainer_sees_health(p_trainer text, p_customer text) returns boolean
language sql stable as $$
  select p_trainer is not null and p_customer is not null and (
       exists (select 1 from public.kv_store where key like 'custpkg:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer
                 and value->>'status' in ('active','used_up','expired'))
    or exists (select 1 from public.kv_store where key like 'booking:%' and value->>'trainerId' = p_trainer and value->>'customerId' = p_customer
                 and value->>'status' in ('pending','confirmed','completed','no_show')))
$$;

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

create or replace function app_private.w_booking(c app_private.ctx_t, p_key text, o jsonb, n jsonb) returns jsonb
language plpgsql as $$
declare
  t jsonb; pkg jsonb; cu jsonb; d date; tm text; start_ts timestamptz; lead numeric; tid text; open_n int; pid text;
  mode text; pn jsonb; other_conf int; from_s text; to_s text;
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
    -- the first customer to book a time gets it: it goes onto the trainer's schedule straight away
    if exists (select 1 from public.kv_store where key like 'booking:%' and value->>'trainerId' = tid and value->>'bookingDate' = n->>'bookingDate'
                  and value->>'bookingTime' = tm and value->>'status' in ('pending','confirmed')) then
      perform app_private.err(409, 'locked');
    end if;

    select count(*) into open_n from public.kv_store
     where key like 'booking:%' and value->>'packageInstanceId' = pid and value->>'status' in ('pending','confirmed');
    if open_n >= (pkg->>'remainingSessions')::int then perform app_private.err(400, 'no_package'); end if;
    if (select count(*) from public.kv_store where key like 'booking:%' and value->>'customerId' = c.uid
           and value->>'status' in ('pending','confirmed') and value->>'bookingDate' >= app_private.today()::text) >= 30 then
      perform app_private.err(429, 'too_many_open');
    end if;
    cu := (select value from public.kv_store where key = c.ukey);
    return jsonb_build_object('id', substr(p_key, 9), 'customerId', c.uid, 'customerName', cu->>'name', 'trainerId', tid,
        'trainerName', t->>'name', 'packageInstanceId', pid, 'bookingDate', n->>'bookingDate', 'bookingTime', tm,
        'status', 'confirmed', 'sessionMode', 'solo', 'partnerNames', '[]'::jsonb,
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
      if other_conf >= 2 or (other_conf >= 1 and mode is distinct from 'duo') then perform app_private.err(409, 'locked'); end if;
    end if;
    if to_s in ('completed','no_show') and from_s = 'confirmed' then
      n := n || jsonb_build_object('completedAt', to_char(now() at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'));
    end if;
    return n;
  end if;
  perform app_private.err(403, 'forbidden');
  return null;
end $$;

-- make the API pick up the changes straight away
notify pgrst, 'reload schema';

-- result: the first line should say ok; the second tells how many packages (if any) name no trainer and so can no longer be used for booking
select 'new rules installed' as item,
       case when exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'app_private' and p.proname = 'trainer_sees_health') then 'ok' else 'MISSING' end as result
union all
select 'packages that name no trainer (cannot be used any more)',
       (select count(*)::text from public.kv_store where key like 'custpkg:%' and coalesce(value->>'trainerId', '') = '' and value->>'status' = 'active' and coalesce((value->>'remainingSessions')::int, 0) > 0);
