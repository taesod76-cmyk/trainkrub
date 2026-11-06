-- =====================================================================
-- TRAINKRUB update (round 18): pair and small-group training (up to 3 people in the same time slot).
-- For a database that already ran 01_install.sql and 02_lockdown.sql (and the updates 03 to 07).
-- Safe to run more than once. Run it BEFORE publishing the website version that goes with it.
--  * a trainer can choose how many customers train in the same time slot: 1 (as it always was), 2 (pair) or 3 (small group)
--  * a customer who books a time that already has people in it (and still has room) joins them: that makes it a pair or a group.
--    Each person books and uses up a session of their own package
--  * a customer can ask to train alone ("no one else in this time"); it only works for a time nobody booked yet and
--    only with a trainer who takes more than one person
--  * the people already booked at that time get a notice that someone joined (they never see who)
-- It only replaces server functions; no stored data is changed. Every trainer stays at "1 per time" until they change it themselves.
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

-- make the API pick up the changes straight away
notify pgrst, 'reload schema';

-- result: the first line should say ok; the second tells how many trainers already allow more than one person per time (0 right after this update)
select 'group-session rules installed' as item,
       case when exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'app_private' and p.proname = 'notify_joined') then 'ok' else 'MISSING' end as result
union all
select 'trainers taking more than one person per time',
       (select count(*)::text from public.kv_store where key like 'trainer:%' and coalesce(value->>'maxPerSlot', '1') <> '1');
