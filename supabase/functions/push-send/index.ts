// =====================================================================
// TRAINKRUB "push-send": sends the pop-up notifications to phones.
// Paste this whole file into a new Supabase Edge Function named  push-send
// (Verify JWT must be OFF: the database calls it with its own secret).
// The database calls this function every time a new in-app notification is made.
// Nothing secret lives in this file: the database holds the secret and the keys.
// =====================================================================

const SUPABASE_URL: string = (typeof Deno !== 'undefined' && Deno.env.get('SUPABASE_URL')) || 'https://eauzvihirpfcjkwyqgel.supabase.co';
// the public (publishable) key of the website, the same one that is in index.html
const API_KEY = 'sb_publishable_TYxnhvbPvCHCycPFWioahA_k16FmgnQ';
const SITE = 'https://taesod76-cmyk.github.io/trainkrub/';

const enc = new TextEncoder();

function b64u(buf: Uint8Array): string {
  let s = '';
  for (let i = 0; i < buf.length; i++) s += String.fromCharCode(buf[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64u(str: string): Uint8Array {
  let s = str.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function concat(...parts: Uint8Array[]): Uint8Array {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}

/* RFC 8291 (Web Push message encryption, aes128gcm). `fixed` is only for the test with the RFC's own example. */
export async function encryptPayload(p256dh: string, authSecretB64: string, plaintext: Uint8Array, fixed?: any): Promise<Uint8Array> {
  const uaPub = unb64u(p256dh);
  const authSecret = unb64u(authSecretB64);
  const uaKey = await crypto.subtle.importKey('raw', uaPub, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const as = (fixed && fixed.keyPair) || await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', as.publicKey));
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, as.privateKey, 256));
  const salt: Uint8Array = (fixed && fixed.salt) || crypto.getRandomValues(new Uint8Array(16));
  const ikm = await hkdf(authSecret, ecdh, concat(enc.encode('WebPush: info\0'), uaPub, asPub), 32);
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12);
  const aes = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, concat(plaintext, new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 0x10, 0]);            // record size 4096
  return concat(salt, rs, new Uint8Array([asPub.length]), asPub, ct);
}

/* VAPID: proves to the phone makers' push servers that the message comes from this website's server. */
export async function vapidHeader(endpoint: string, privJwk: any, pubB64u: string, key?: CryptoKey): Promise<string> {
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const claims = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SITE })));
  const k = key || await crypto.subtle.importKey('jwk', privJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k, enc.encode(head + '.' + claims)));
  return 'vapid t=' + head + '.' + claims + '.' + b64u(sig) + ', k=' + pubB64u;
}

export async function makeVapidKeys(): Promise<{ pub: string; priv: string }> {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk: any = await crypto.subtle.exportKey('jwk', kp.privateKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { pub: b64u(raw), priv: JSON.stringify({ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, d: jwk.d }) };
}

async function rpc(fn: string, args: any): Promise<{ status: number; data: any }> {
  const res = await fetch(SUPABASE_URL + '/rest/v1/rpc/' + fn, {
    method: 'POST',
    headers: { apikey: API_KEY, Authorization: 'Bearer ' + API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
  });
  let data: any = null;
  try { data = await res.json(); } catch (_e) { /* empty answer */ }
  return { status: res.status, data };
}

function reply(obj: any, status = 200): Response {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json' } });
}

async function sendOne(sub: any, body: Uint8Array, vapidKey: any, vapidPub: string, fetchImpl: any): Promise<{ result: string; code: number }> {
  let host = '?';
  try { host = new URL(sub.endpoint).host; } catch (_e) { /* ignore */ }
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const payload = await encryptPayload(sub.p256dh, sub.auth, body);
      const res = await fetchImpl(sub.endpoint, {
        method: 'POST',
        headers: {
          'Content-Encoding': 'aes128gcm',
          'Content-Type': 'application/octet-stream',
          TTL: '86400',
          Urgency: 'high',
          Authorization: await vapidHeader(sub.endpoint, null, vapidPub, vapidKey),
        },
        body: payload,
        signal: AbortSignal.timeout(8000),
      });
      const code = res.status;
      try { await res.arrayBuffer(); } catch (_e) { /* ignore */ }
      if (code >= 200 && code < 300) return { result: 'sent', code };
      if (code === 404 || code === 410) return { result: 'dead', code };
      if ((code >= 500 || code === 429) && attempt === 0) { await new Promise((r) => setTimeout(r, 600)); continue; }
      return { result: 'failed', code };
    } catch (_e) {
      if (attempt === 1) return { result: 'failed', code: 0 };
      await new Promise((r) => setTimeout(r, 600));
    }
  }
  return { result: 'failed', code: 0 };
}

/* `deps` lets the tests swap the network. */
export async function handle(req: Request, deps?: any): Promise<Response> {
  const call = (deps && deps.rpc) || rpc;
  const fetchImpl = (deps && deps.fetch) || fetch;
  if (req.method !== 'POST') return reply({ ok: false, reason: 'method' }, 405);
  const secret = req.headers.get('x-push-secret') || '';
  if (!secret) return reply({ ok: false, reason: 'unauthorized' }, 401);
  let body: any = {};
  try { body = await req.json(); } catch (_e) { /* no body */ }
  const cmd = String((body && body.cmd) || '');
  const key = cmd === 'notif' ? String(body.key || '') : null;
  if (cmd !== 'init' && cmd !== 'notif') return reply({ ok: false, reason: 'cmd' }, 400);
  if (cmd === 'notif' && !/^notif:[A-Za-z0-9_.@-]{1,80}$/.test(key || '')) return reply({ ok: false, reason: 'key' }, 400);

  const take = await call('app_push_take', { p_secret: secret, p_key: key });
  if (take.status === 403 || take.status === 401) return reply({ ok: false, reason: 'unauthorized' }, 401);
  if (take.status !== 200 || !take.data) return reply({ ok: false, reason: 'database', status: take.status }, 502);
  let vapid = take.data.vapid;
  if (!vapid) {
    const mk = await makeVapidKeys();
    const st = await call('app_push_vapid_set', { p_secret: secret, p_pub: mk.pub, p_priv: mk.priv });
    if (st.status !== 200 || !st.data || !st.data.pub) return reply({ ok: false, reason: 'vapid_store', status: st.status }, 502);
    // another call may have stored its own pair first: always use what the database holds
    const again = await call('app_push_take', { p_secret: secret, p_key: key });
    vapid = again.data && again.data.vapid;
    if (!vapid) return reply({ ok: false, reason: 'vapid_missing' }, 502);
    if (cmd === 'init') return reply({ ok: true, ready: true, created: true });
    take.data = again.data;
  }
  if (cmd === 'init') return reply({ ok: true, ready: true, created: false });

  const subs: any[] = take.data.subs || [];
  if (!subs.length) return reply({ ok: true, sent: 0, dead: 0, failed: 0 });
  const note = {
    title: String(take.data.title || '\u0e40\u0e17\u0e23\u0e19\u0e04\u0e23\u0e31\u0e1a').slice(0, 80),
    body: String(take.data.body || '').slice(0, 300),
    tag: String(take.data.tag || ''),
    url: './?go=notif',
  };
  const bytes = enc.encode(JSON.stringify(note));
  const vapidKey = await crypto.subtle.importKey('jwk', JSON.parse(vapid.priv), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const results = await Promise.all(subs.map((s) => sendOne(s, bytes, vapidKey, vapid.pub, fetchImpl)));
  const dead: string[] = [];
  let sent = 0, failed = 0;
  const detail: string[] = [];
  results.forEach((r, i) => {
    if (r.result === 'sent') sent++; else if (r.result === 'dead') dead.push(subs[i].endpoint); else failed++;
    let host = '?'; try { host = new URL(subs[i].endpoint).host; } catch (_e) { /* ignore */ }
    detail.push(host + ':' + r.code);
  });
  await call('app_push_done', { p_secret: secret, p_key: key, p_sent: sent, p_failed: failed, p_dead: dead, p_detail: detail.join(' ').slice(0, 280) });
  return reply({ ok: true, sent, dead: dead.length, failed });
}

if (typeof Deno !== 'undefined' && (Deno as any).serve) {
  (Deno as any).serve((req: Request) => handle(req).catch((e) => reply({ ok: false, reason: 'error', message: String(e && e.message || e).slice(0, 200) }, 500)));
}
