#!/usr/bin/env python3
"""TRAINKUB restore helper: turns a backup into SQL files that are pasted into Supabase > SQL Editor, one at a time.
It never touches the database itself, so the person doing the restore sees (and approves) what will run.

  python3 restore_make_sql.py --cms trainkub-backup-XXXX.tar.gz.cms --key backup_private.pem --out RESTORE
  python3 restore_make_sql.py --pack pack.tar.gz --out RESTORE --mode missing --prefix booking,custpkg

Modes (what happens to a row that is already in the database):
  missing    (default) only rows that are gone are put back; rows that exist stay as they are. The safe choice after something was deleted.
  overwrite  rows are put back and a row that exists is replaced by the copy from the backup (use it to undo a wrong change).
  replace    the tables are emptied first, then filled with the backup: for a brand-new database (after 01_install.sql) or a total reset.
Filters: --prefix booking,custpkg (kv_store groups)   --keys customer:c_ab12,trainer:t_x   --tables kv_store,cred,push_config,push_subs,audit
"""
import argparse, io, json, os, subprocess, sys, tarfile, tempfile

SPEC = {
    'kv_store':    {'full': 'public.kv_store',         'file': 'public.kv_store.jsonl',         'cols': ['key', 'value', 'updated_at'], 'pk': 'key', 'jsonb': ['value']},
    'cred':        {'full': 'app_private.cred',        'file': 'app_private.cred.jsonl',        'cols': ['ukey', 'pw_hash', 'updated_at'], 'pk': 'ukey'},
    'push_config': {'full': 'app_private.push_config', 'file': 'app_private.push_config.jsonl', 'cols': ['k', 'v', 'updated_at'], 'pk': 'k'},
    'push_subs':   {'full': 'app_private.push_subs',   'file': 'app_private.push_subs.jsonl',   'cols': ['id', 'user_id', 'endpoint', 'p256dh', 'auth', 'ua', 'created_at', 'seen_at'], 'pk': 'id', 'seq': 'id'},
    'audit':       {'full': 'app_private.audit',       'file': 'app_private.audit.jsonl',       'cols': ['id', 'at', 'actor', 'action', 'target', 'ok', 'ip', 'detail'], 'pk': 'id', 'seq': 'id'},
}
DEFAULT_TABLES = ['kv_store', 'cred', 'push_config', 'push_subs']


def find_openssl():
    """openssl on PATH, or the one that comes with Git for Windows"""
    import shutil
    found = shutil.which('openssl')
    if found:
        return found
    for c in (r'C:\Program Files\Git\usr\bin\openssl.exe', r'C:\Program Files\Git\mingw64\bin\openssl.exe',
              r'C:\Program Files (x86)\Git\usr\bin\openssl.exe'):
        if os.path.exists(c):
            return c
    sys.exit('openssl was not found. Install Git for Windows (it brings openssl), or put openssl on the PATH.')


def read_pack(a):
    if a.pack:
        data = open(a.pack, 'rb').read()
    else:
        if not (a.cms and a.key):
            sys.exit('give --pack, or --cms and --key')
        r = subprocess.run([find_openssl(), 'cms', '-decrypt', '-binary', '-inform', 'DER', '-in', a.cms, '-inkey', a.key],
                           capture_output=True)
        if r.returncode != 0:
            sys.exit('could not open the backup (wrong key?): ' + r.stderr.decode(errors='replace')[:200])
        data = r.stdout
    return tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')


def member_bytes(tf, name):
    """a file of the pack by name, whether or not the pack wrote it as ./name"""
    for m in tf.getmembers():
        if m.name.lstrip('./') == name:
            return tf.extractfile(m).read()
    sys.exit('the backup does not contain ' + name)


def dq(s):
    """a dollar-quote tag that does not occur in the data"""
    i = 0
    while True:
        tag = '$tk%d$' % i if i else '$tk$'
        if tag not in s:
            return tag
        i += 1


def trigger_off(on):
    verb = 'disable' if on else 'enable'
    return ("do $$ begin if exists (select 1 from pg_trigger where tgname = 'kv_store_push_notif' and tgrelid = 'public.kv_store'::regclass) "
            "then alter table public.kv_store %s trigger kv_store_push_notif; end if; end $$;\n" % verb)


def chunk_sql(name, rows, mode, first_of_table):
    sp = SPEC[name]
    body = json.dumps(rows, ensure_ascii=False, separators=(',', ':'))
    tag = dq(body)
    cols = ', '.join(sp['cols'])
    sel = ', '.join('r.' + c for c in sp['cols'])
    out = []
    if name == 'kv_store':
        out.append(trigger_off(True))        # restoring old notices must not pop up on people's phones again
    if mode == 'replace' and first_of_table:
        out.append('delete from %s;\n' % sp['full'])
    ins = 'insert into %s (%s)%s\nselect %s from jsonb_populate_recordset(null::%s, %s%s%s::jsonb) r\n' % (sp['full'], cols, '', sel, sp['full'], tag, body, tag)
    if mode == 'missing':
        ins += 'on conflict do nothing;\n'
    elif mode == 'overwrite':
        sets = ', '.join('%s = excluded.%s' % (c, c) for c in sp['cols'] if c != sp['pk'])
        ins += 'on conflict (%s) do update set %s;\n' % (sp['pk'], sets)
    else:
        ins += ';\n'
    out.append(ins)
    if name == 'kv_store':
        out.append(trigger_off(False))
    return ''.join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--cms'); ap.add_argument('--key'); ap.add_argument('--pack')
    ap.add_argument('--out', required=True)
    ap.add_argument('--mode', default='missing', choices=['missing', 'overwrite', 'replace'])
    ap.add_argument('--tables', default=','.join(DEFAULT_TABLES))
    ap.add_argument('--prefix', default='')
    ap.add_argument('--keys', default='')
    ap.add_argument('--max-bytes', type=int, default=900000)
    a = ap.parse_args()

    tf = read_pack(a)
    manifest = json.loads(member_bytes(tf, 'manifest.json'))
    want = [t.strip() for t in a.tables.split(',') if t.strip()]
    for t in want:
        if t not in SPEC:
            sys.exit('unknown table: ' + t)
    prefixes = [p.strip().rstrip(':') for p in a.prefix.split(',') if p.strip()]
    keys = {k.strip() for k in a.keys.split(',') if k.strip()}
    if a.mode == 'replace' and (prefixes or keys):
        sys.exit('replace empties whole tables: do not combine it with --prefix or --keys')

    os.makedirs(a.out, exist_ok=True)
    for f in os.listdir(a.out):
        if f.startswith('RESTORE_') and f.endswith('.sql'):
            os.remove(os.path.join(a.out, f))
    files, summary = [], []
    cur, cur_size = [], 0

    def flush():
        nonlocal cur, cur_size
        if not cur:
            return
        path = os.path.join(a.out, 'RESTORE_%02d.sql' % (len(files) + 1))
        with open(path, 'w', encoding='utf-8') as f:
            f.write('-- TRAINKUB restore, part %d. Mode: %s. Backup taken: %s\n' % (len(files) + 1, a.mode, manifest.get('stamp', '?')))
            f.write('-- Run the parts in order. Each part is complete on its own.\n')
            f.write(''.join(cur))
        files.append(path); cur, cur_size = [], 0

    for name in want:
        sp = SPEC[name]
        member = sp['file']
        raw = member_bytes(tf, member).decode('utf-8').splitlines()
        rows = [json.loads(x) for x in raw if x.strip()]
        if name == 'kv_store' and (prefixes or keys):
            rows = [r for r in rows if r['key'] in keys or r['key'].split(':', 1)[0] in prefixes]
        summary.append((name, len(rows)))
        batch, size, first = [], 0, True
        def emit():
            nonlocal batch, size, first, cur, cur_size
            if not batch and not (first and a.mode == 'replace'):
                return
            sql = chunk_sql(name, batch, a.mode, first)
            if cur and cur_size + len(sql) > a.max_bytes:
                flush()
            cur.append(sql); cur_size += len(sql)
            first = False; batch = []; size = 0
        for r in rows:
            n = len(json.dumps(r, ensure_ascii=False))
            if batch and size + n > a.max_bytes // 2:
                emit()
            batch.append(r); size += n
        emit()
        if sp.get('seq') and rows:
            cur.append("select setval(pg_get_serial_sequence('%s', '%s'), (select coalesce(max(%s), 1) from %s));\n" % (sp['full'], sp['seq'], sp['seq'], sp['full']))
    flush()

    with open(os.path.join(a.out, 'RESTORE_README.txt'), 'w', encoding='utf-8') as f:
        f.write('Backup taken: %s\nMode: %s\n' % (manifest.get('stamp', '?'), a.mode))
        for n, c in summary:
            f.write('  %-12s %d rows\n' % (n, c))
        f.write('\nPaste RESTORE_01.sql ... RESTORE_%02d.sql into Supabase > SQL Editor, one after the other, and press Run on each.\n' % len(files))
    print('backup taken:', manifest.get('stamp', '?'), '| mode:', a.mode)
    for n, c in summary:
        print('  %-12s %d rows' % (n, c))
    print('written: %d file(s) in %s' % (len(files), a.out))
    return 0


if __name__ == '__main__':
    sys.exit(main())
