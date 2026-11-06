#!/usr/bin/env python3
"""TRAINKUB backup check.
Reads the dumped tables (one JSON row per line), makes sure they are whole, and compares the numbers with the last good day.
  exit 0  all good (today's numbers become the new "last good day")
  exit 1  the dump itself is broken (unreadable rows, an empty app table)
  exit 2  data looks like it went missing: the numbers are NOT taken as the new normal, so the alarm repeats every day until
          somebody looks (and, if the drop was intended, runs the job once with ACCEPT=1)
Nothing here prints counts or names: the log of a public repository is public. It prints only table / group names and percentages.
"""
import argparse, hashlib, json, os, sys

TABLES = ['public.kv_store', 'app_private.cred', 'app_private.push_config', 'app_private.push_subs', 'app_private.audit']
# groups of rows in kv_store (the part of the key before the first colon)
CORE = {'admin', 'trainer', 'customer', 'custpkg', 'booking'}             # a few missing rows already matter
IGNORE = {'notif', 'system'}                                              # inboxes are trimmed on purpose; system rows are housekeeping
NO_DROP_CHECK = {'app_private.push_subs', 'app_private.audit'}            # devices unsubscribe, the log is trimmed after 180 days


def load(work):
    counts, kv, sha = {}, {}, {}
    for t in TABLES:
        path = os.path.join(work, t + '.jsonl')
        if not os.path.exists(path):
            raise SystemExit('missing dump file: ' + t)
        n, h = 0, hashlib.sha256()
        with open(path, 'rb') as f:
            for raw in f:
                if not raw.strip():
                    continue
                h.update(raw)
                try:
                    row = json.loads(raw)
                except Exception:
                    print('a row of %s is not valid JSON' % t); sys.exit(1)
                n += 1
                if t == 'public.kv_store':
                    g = str(row.get('key', '')).split(':', 1)[0]
                    kv[g] = kv.get(g, 0) + 1
        counts[t] = n
        sha[t] = h.hexdigest()
    return counts, kv, sha


def lost(prev, now):
    return max(0, prev - now)


def compare(prev, counts, kv):
    """Returns a list of short sentences (no numbers of customers) for everything that dropped too far."""
    alarms = []
    pc, pk = prev.get('counts', {}), prev.get('kv', {})
    for t in TABLES:
        if t in NO_DROP_CHECK or t not in pc:
            continue
        l, p = lost(pc[t], counts[t]), pc[t]
        if t == 'app_private.cred':
            if l >= 2 and l >= 0.1 * p:
                alarms.append('sign-in records dropped by %d%%' % round(100 * l / p))
        elif t == 'app_private.push_config':
            if l >= 1:
                alarms.append('push settings are missing')
        elif t == 'public.kv_store':
            keep = lambda d: sum(v for g, v in d.items() if g not in IGNORE)
            lt, pt = lost(keep(pk), keep(kv)), keep(pk)
            if pt and lt >= 5 and lt >= 0.1 * pt:
                alarms.append('app data dropped by %d%% in total' % round(100 * lt / pt))
    for g, p in sorted(pk.items()):
        if g in IGNORE:
            continue
        n = kv.get(g, 0)
        l = lost(p, n)
        if n == 0 and p >= 1:
            alarms.append('every "%s" row is gone' % g)
        elif g in CORE and l >= 2 and l >= 0.1 * p:
            alarms.append('"%s" rows dropped by %d%%' % (g, round(100 * l / p)))
        elif g not in CORE and l >= 3 and l >= 0.2 * p:
            alarms.append('"%s" rows dropped by %d%%' % (g, round(100 * l / p)))
    return alarms


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--work', required=True)
    ap.add_argument('--state', required=True)
    ap.add_argument('--stamp', default='')
    ap.add_argument('--accept', action='store_true')
    ap.add_argument('--simulate-alarm', action='store_true')
    a = ap.parse_args()

    counts, kv, sha = load(a.work)
    if counts['public.kv_store'] == 0:
        print('the app data table is empty'); return 1
    manifest = {'format': 1, 'stamp': a.stamp, 'tables': TABLES, 'counts': counts, 'kv': kv, 'sha256': sha}
    with open(os.path.join(a.work, 'manifest.json'), 'w') as f:
        json.dump(manifest, f, indent=1, sort_keys=True)

    last_path = os.path.join(a.state, 'last.json')
    prev = None
    if os.path.exists(last_path):
        try:
            prev = json.load(open(last_path))
        except Exception:
            prev = None
    alarms = []
    if prev and not a.accept:
        alarms = compare(prev, counts, kv)
    if a.simulate_alarm:
        alarms.append('TEST: this alarm was asked for on purpose')

    if alarms:
        print('ALARM: the data looks like it went missing since the last good day')
        for x in alarms:
            print(' - ' + x)
        print('A backup was still made. Nothing was taken as the new normal, so this alarm repeats until someone looks.')
        print('If the drop was intended, run the "Nightly backup" job once with "accept" ticked.')
        return 2
    os.makedirs(a.state, exist_ok=True)
    with open(last_path, 'w') as f:
        json.dump({'stamp': a.stamp, 'counts': counts, 'kv': kv}, f)
    print('checked %d tables: ok%s' % (len(TABLES), '' if prev else ' (first run: today is the starting point)'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
