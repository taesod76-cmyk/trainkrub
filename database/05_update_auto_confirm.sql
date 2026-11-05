-- =====================================================================
-- TRAINKRUB update (round 14): bookings go straight onto the trainer's schedule.
-- For a database that already ran 01_install.sql and 02_lockdown.sql (and the updates 03 and 04).
-- Safe to run more than once. Run it BEFORE publishing the website version that goes with it.
--  * a customer's booking is confirmed at once (the trainer already set the notice time), the first customer to book a time gets it
--  * requests that are still waiting today are turned into bookings on the schedule
--    (a time asked for by two people goes to the one who asked first, the other is declined; times already in the past are closed)
-- =====================================================================

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
    if pkg is null or pkg->>'customerId' <> c.uid or (pkg->>'trainerId' is not null and pkg->>'trainerId' <> tid)
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

-- requests that are still waiting become bookings on the schedule
with w as (
  select key, value,
         row_number() over (partition by value->>'trainerId', value->>'bookingDate', value->>'bookingTime'
                            order by value->>'createdAt', key) as rn
    from public.kv_store
   where key like 'booking:%' and value->>'status' = 'pending'
)
update public.kv_store k
   set value = k.value || case
         when w.value->>'bookingDate' < app_private.today()::text then jsonb_build_object('status', 'cancelled')
         when exists (select 1 from public.kv_store x
                       where x.key like 'booking:%' and x.value->>'status' = 'confirmed'
                         and x.value->>'trainerId' = w.value->>'trainerId' and x.value->>'bookingDate' = w.value->>'bookingDate'
                         and x.value->>'bookingTime' = w.value->>'bookingTime') then jsonb_build_object('status', 'rejected')
         when w.rn = 1 then jsonb_build_object('status', 'confirmed', 'sessionMode', 'solo', 'partnerNames', '[]'::jsonb)
         else jsonb_build_object('status', 'rejected') end,
       updated_at = now()
  from w
 where k.key = w.key;

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
              'app_find_trainer','app_admin_maintain','app_admin_stats','app_ping','app_finish_apply') loop
    execute format('grant execute on function %s to anon, authenticated', f.sig);
  end loop;
end $$;


-- make the API pick up the changes straight away
notify pgrst, 'reload schema';
