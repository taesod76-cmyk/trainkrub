// =====================================================================
// TRAINKUB "line": the one server piece that talks to LINE.
// Paste this whole file into a new Supabase Edge Function named  line
// (Verify JWT must be OFF: LINE and the database call it with their own proofs).
// What it does
//   1. webhook   : LINE tells it when someone adds / blocks the Official Account (checked with the channel secret).
//   2. notices   : the database asks it to send a notice to a person's LINE (checked with the shared secret).
//   3. sign in   : the website, opened inside LINE, sends the LINE sign-in token; this function checks it with LINE
//                  and asks the database to sign the person in or to link the LINE account.
//   4. setup/ping: make the two chat menus, check the connection (asked by the owner through the database).
// Secrets live only in Supabase "Edge Function secrets", never in this file:
//   LINE_CHANNEL_SECRET        (Messaging API channel: Basic settings > Channel secret)
//   LINE_CHANNEL_ACCESS_TOKEN  (Messaging API channel: Messaging API > Channel access token (long-lived))
//   DB_SECRET                  (the shared secret kept in the database; the setup guide shows how to read it once)
// =====================================================================

const SUPABASE_URL: string = (typeof Deno !== 'undefined' && Deno.env.get('SUPABASE_URL')) || 'https://eauzvihirpfcjkwyqgel.supabase.co';
// the public (publishable) key of the website, the same one that is in index.html
const API_KEY = 'sb_publishable_TYxnhvbPvCHCycPFWioahA_k16FmgnQ';
const SITE = 'https://taesod76-cmyk.github.io/trainkrub/';
const LIFF_ID = '2012632218-KR7p4DNo';
const LOGIN_CHANNEL_ID = '2012632218';
const API = 'https://api.line.me';
const API_DATA = 'https://api-data.line.me';

const enc = new TextEncoder();

function envOf(deps: any, k: string): string {
  // a secret pasted with a space or a new line at its end must still work, so the value is trimmed
  if (deps && deps.env) return String(deps.env(k) || '').trim();
  return String((typeof Deno !== 'undefined' && (Deno as any).env.get(k)) || '').trim();
}
function liffUrl(deps: any): string { return 'https://liff.line.me/' + (envOf(deps, 'LIFF_ID') || LIFF_ID); }
function siteUrl(deps: any): string { return envOf(deps, 'SITE_URL') || SITE; }
function allowedOrigins(deps: any): string[] {
  const out = ['https://taesod76-cmyk.github.io'];
  const extra = envOf(deps, 'ALLOWED_ORIGINS');
  if (extra) for (const o of extra.split(',')) { const t = o.trim().replace(/\/+$/, ''); if (/^https:\/\/[A-Za-z0-9.-]+(:[0-9]{2,5})?$/.test(t)) out.push(t); }
  return out;
}

async function rpc(fn: string, args: any): Promise<{ status: number; data: any }> {
  const res = await fetch(SUPABASE_URL + '/rest/v1/rpc/' + fn, {
    method: 'POST',
    headers: { apikey: API_KEY, Authorization: 'Bearer ' + API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(args),
    signal: AbortSignal.timeout(9000),
  });
  let data: any = null;
  try { data = await res.json(); } catch (_e) { /* empty answer */ }
  return { status: res.status, data };
}

function json(obj: any, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json', ...(extra || {}) } });
}

/* constant-time comparison of two strings */
function same(a: string, b: string): boolean {
  const x = enc.encode(a), y = enc.encode(b);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

/* LINE signs the exact bytes of the webhook body: base64(HMAC-SHA256(body, channel secret)) */
export async function lineSignature(rawBody: string, channelSecret: string): Promise<string> {
  const k = await crypto.subtle.importKey('raw', enc.encode(channelSecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(rawBody)));
  let s = '';
  for (let i = 0; i < sig.length; i++) s += String.fromCharCode(sig[i]);
  return btoa(s);
}

/* ---------------------------------------------------------------- talking to LINE */
async function lineCall(deps: any, base: string, path: string, init: any): Promise<{ status: number; data: any }> {
  const f = (deps && deps.fetch) || fetch;
  const tok = envOf(deps, 'LINE_CHANNEL_ACCESS_TOKEN');
  if (!tok) return { status: 0, data: { message: 'no_token' } };
  const headers: Record<string, string> = { Authorization: 'Bearer ' + tok, ...(init.headers || {}) };
  try {
    const res = await f(base + path, { ...init, headers, signal: AbortSignal.timeout(9000) });
    let data: any = null;
    try { data = await res.json(); } catch (_e) { /* empty answer */ }
    return { status: res.status, data };
  } catch (_e) {
    return { status: 0, data: { message: 'network' } };
  }
}

/* true / false / null (null = LINE could not tell us right now) */
async function isFriend(deps: any, sub: string): Promise<boolean | null> {
  const r = await lineCall(deps, API, '/v2/bot/profile/' + encodeURIComponent(sub), { method: 'GET' });
  if (r.status === 200) return true;
  if (r.status === 404) return false;
  return null;
}

async function replyText(deps: any, replyToken: string, text: string) {
  if (!replyToken) return;
  await lineCall(deps, API, '/v2/bot/message/reply', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ replyToken, messages: [{ type: 'text', text: text.slice(0, 1800) }] }),
  });
}

function uuid(): string { return (crypto as any).randomUUID(); }

/* the LINE sign-in token the page got inside LINE: LINE itself says who it belongs to */
export async function verifyIdToken(deps: any, idToken: string): Promise<{ sub: string; name: string; picture: string } | null> {
  if (!/^[A-Za-z0-9._-]{20,4000}$/.test(idToken || '')) return null;
  const f = (deps && deps.fetch) || fetch;
  const clientId = envOf(deps, 'LINE_LOGIN_CHANNEL_ID') || LOGIN_CHANNEL_ID;
  try {
    const res = await f(API + '/oauth2/v2.1/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'id_token=' + encodeURIComponent(idToken) + '&client_id=' + encodeURIComponent(clientId),
      signal: AbortSignal.timeout(9000),
    });
    if (res.status !== 200) return null;
    const d: any = await res.json();
    if (!d || d.iss !== 'https://access.line.me' || String(d.aud) !== clientId) return null;
    if (typeof d.exp !== 'number' || d.exp * 1000 < Date.now()) return null;
    if (typeof d.sub !== 'string' || !/^U[0-9a-f]{32}$/.test(d.sub)) return null;
    return { sub: d.sub, name: String(d.name || '').slice(0, 60), picture: /^https:\/\/[A-Za-z0-9.-]+\/[^\s]*$/.test(String(d.picture || '')) ? String(d.picture).slice(0, 300) : '' };
  } catch (_e) {
    return null;
  }
}

/* ---------------------------------------------------------------- the two chat menus */
type Cell = { label: string; go?: string };
const CUSTOMER_CELLS: Cell[] = [
  { label: 'หน้าหลัก', go: 'dashboard' }, { label: 'หาเทรนเนอร์', go: 'trainers' }, { label: 'การจองของฉัน', go: 'mybookings' },
  { label: 'แจ้งเตือน', go: 'notif' }, { label: 'โปรไฟล์', go: 'profile' }, { label: 'เปิดแอป' },
];
const TRAINER_CELLS: Cell[] = [
  { label: 'หน้าหลัก', go: 'dashboard' }, { label: 'คำขอจอง', go: 'requests' }, { label: 'ตารางงาน', go: 'schedule' },
  { label: 'ลูกค้า', go: 'customers' }, { label: 'การชำระเงิน', go: 'payments' }, { label: 'โปรไฟล์', go: 'profile' },
];
export function menuJson(deps: any, name: string, cells: Cell[]): any {
  const xs = [0, 833, 1666], ws = [833, 833, 834];
  return {
    size: { width: 2500, height: 1686 }, selected: true, name, chatBarText: 'เมนูเทรนคับ',
    areas: cells.map((c, i) => ({
      bounds: { x: xs[i % 3], y: i < 3 ? 0 : 843, width: ws[i % 3], height: 843 },
      action: { type: 'uri', label: c.label.slice(0, 20), uri: liffUrl(deps) + (c.go ? '?go=' + c.go : '') },
    })),
  };
}

async function setupMenus(deps: any, secret: string): Promise<{ ok: boolean; detail: string }> {
  const f = (deps && deps.fetch) || fetch;
  const out: Record<string, string> = {};
  const parts: string[] = [];
  for (const [role, cells] of [['customer', CUSTOMER_CELLS], ['trainer', TRAINER_CELLS]] as [string, Cell[]][]) {
    const mk = await lineCall(deps, API, '/v2/bot/richmenu', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(menuJson(deps, 'TRAINKUB-' + role + '-' + Date.now(), cells)),
    });
    if (mk.status !== 200 || !mk.data || !/^richmenu-[0-9a-f]{32}$/.test(String(mk.data.richMenuId || ''))) { parts.push(role + ' create ' + mk.status + ' ' + String((mk.data && mk.data.message) || '').slice(0, 60)); return { ok: false, detail: parts.join('; ') }; }
    const id = String(mk.data.richMenuId);
    let img: Uint8Array | null = null;
    try {
      const r = await f(siteUrl(deps) + 'richmenu/' + role + '.png', { signal: AbortSignal.timeout(9000) });
      if (r.status === 200) img = new Uint8Array(await r.arrayBuffer());
      else parts.push(role + ' image ' + r.status);
    } catch (_e) { parts.push(role + ' image network'); }
    if (!img || img.length < 1000 || img.length > 1000000) { parts.push(role + ' image missing/too big'); return { ok: false, detail: parts.join('; ') }; }
    const up = await lineCall(deps, API_DATA, '/v2/bot/richmenu/' + id + '/content', { method: 'POST', headers: { 'Content-Type': 'image/png' }, body: img });
    if (up.status !== 200) { parts.push(role + ' upload ' + up.status + ' ' + String((up.data && up.data.message) || '').slice(0, 60)); return { ok: false, detail: parts.join('; ') }; }
    out[role] = id;
    parts.push(role + ' ok');
  }
  const dflt = await lineCall(deps, API, '/v2/bot/user/all/richmenu/' + out.customer, { method: 'POST' });
  parts.push('default ' + dflt.status);
  // remember the two menus in the database
  const call = (deps && deps.rpc) || rpc;
  const st = await call('app_line_conf', { p_secret: secret, p_menu_customer: out.customer, p_menu_trainer: out.trainer });
  parts.push('stored ' + st.status);
  // remove older menus of ours so they do not pile up
  const list = await lineCall(deps, API, '/v2/bot/richmenu/list', { method: 'GET' });
  if (list.status === 200 && list.data && Array.isArray(list.data.richmenus)) {
    for (const m of list.data.richmenus) {
      if (String(m.name || '').startsWith('TRAINKUB-') && m.richMenuId !== out.customer && m.richMenuId !== out.trainer) await lineCall(deps, API, '/v2/bot/richmenu/' + m.richMenuId, { method: 'DELETE' });
    }
  }
  return { ok: dflt.status === 200 && st.status === 200, detail: parts.join('; ') };
}

async function setPersonalMenu(deps: any, secret: string, sub: string, role: string, friend: boolean | null) {
  if (friend === false) return;
  const call = (deps && deps.rpc) || rpc;
  try {
    if (role === 'trainer') {
      const c = await call('app_line_conf', { p_secret: secret });
      const id = c.data && c.data.menuTrainer;
      if (id) await lineCall(deps, API, '/v2/bot/user/' + encodeURIComponent(sub) + '/richmenu/' + id, { method: 'POST' });
    } else {
      await lineCall(deps, API, '/v2/bot/user/' + encodeURIComponent(sub) + '/richmenu', { method: 'DELETE' });   // back to the shared (customer) menu
    }
  } catch (_e) { /* the menu is a nicety, never a reason to fail */ }
}

/* ---------------------------------------------------------------- the three kinds of caller */
const TEXT = {
  welcome: (u: string) => 'ยินดีต้อนรับสู่เทรนคับ 💪\nจองเทรนเนอร์ ดูแพ็กเกจ และรับแจ้งเตือนได้ในไลน์นี้ กดเมนูด้านล่างหรือเปิดแอปที่นี่:\n' + u + '\n\nถ้ามีบัญชีเทรนคับอยู่แล้ว เข้าสู่ระบบครั้งเดียว ระบบจะผูกกับไลน์นี้ให้',
  open: (u: string) => 'เปิดแอปเทรนคับได้ที่นี่:\n' + u,
};

async function onWebhook(deps: any, raw: string, signature: string): Promise<Response> {
  const channelSecret = envOf(deps, 'LINE_CHANNEL_SECRET');
  if (!channelSecret) return json({ ok: false, reason: 'not_configured' }, 503);
  const want = await lineSignature(raw, channelSecret);
  if (!same(want, signature.trim())) {
    // only lengths are written, never a secret: the Edge Function logs then show whether the stored secret is the right size (32 characters)
    console.log('line webhook: signature does not match (LINE_CHANNEL_SECRET length ' + channelSecret.length + ', signature length ' + signature.length + ')');
    return json({ ok: false, reason: 'signature' }, 401);
  }
  let body: any = {};
  try { body = JSON.parse(raw); } catch (_e) { return json({ ok: true }); }
  const events: any[] = Array.isArray(body && body.events) ? body.events.slice(0, 100) : [];
  const call = (deps && deps.rpc) || rpc;
  const secret = envOf(deps, 'DB_SECRET');
  const u = liffUrl(deps);
  await Promise.allSettled(events.map(async (ev) => {
    const sub = ev && ev.source && ev.source.type === 'user' ? String(ev.source.userId || '') : '';
    if (!/^U[0-9a-f]{32}$/.test(sub)) return;
    if (ev.type === 'follow') {
      if (secret) await call('app_line_friend', { p_secret: secret, p_sub: sub, p_friend: true });
      await replyText(deps, String(ev.replyToken || ''), TEXT.welcome(u));
    } else if (ev.type === 'unfollow') {
      if (secret) await call('app_line_friend', { p_secret: secret, p_sub: sub, p_friend: false });
    } else if (ev.type === 'message' && ev.message && ev.message.type === 'text') {
      await replyText(deps, String(ev.replyToken || ''), TEXT.open(u));
    }
  }));
  return json({ ok: true });
}

async function onDatabase(deps: any, body: any, secret: string): Promise<Response> {
  const call = (deps && deps.rpc) || rpc;
  const cmd = String((body && body.cmd) || '');
  if (cmd === 'notif') {
    const key = String(body.key || '');
    if (!/^notif:[A-Za-z0-9_.@-]{1,80}$/.test(key)) return json({ ok: false, reason: 'key' }, 400);
    const take = await call('app_line_take', { p_secret: secret, p_key: key });
    if (take.status === 403 || take.status === 401) return json({ ok: false, reason: 'unauthorized' }, 401);
    if (take.status !== 200 || !take.data) return json({ ok: false, reason: 'database', status: take.status }, 502);
    const to: string[] = Array.isArray(take.data.to) ? take.data.to.filter((s: any) => /^U[0-9a-f]{32}$/.test(String(s))) : [];
    if (!to.length) {
      if (take.data.over) await call('app_line_done', { p_secret: secret, p_kind: 'notif', p_ref: key, p_sent: 0, p_failed: 0, p_detail: 'month allowance used up' });
      return json({ ok: true, sent: 0, over: !!take.data.over });
    }
    const title = String(take.data.title || 'เทรนคับ').slice(0, 80);
    const text = ('🔔 ' + title + (take.data.body ? '\n' + String(take.data.body).slice(0, 400) : '') + '\n\nเปิดดู: ' + liffUrl(deps) + '?go=notif').slice(0, 1800);
    let sent = 0, failed = 0, detail = '';
    for (let i = 0; i < to.length; i += 500) {
      const chunk = to.slice(i, i + 500);
      let r = await lineCall(deps, API, '/v2/bot/message/multicast', {
        method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Line-Retry-Key': uuid() },
        body: JSON.stringify({ to: chunk, messages: [{ type: 'text', text }] }),
      });
      if (r.status === 0 || r.status >= 500) { await new Promise((res) => setTimeout(res, 600)); r = await lineCall(deps, API, '/v2/bot/message/multicast', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Line-Retry-Key': uuid() }, body: JSON.stringify({ to: chunk, messages: [{ type: 'text', text }] }) }); }
      if (r.status === 200) sent += chunk.length; else { failed += chunk.length; detail = String(r.status) + ' ' + String((r.data && r.data.message) || '').slice(0, 100); }
    }
    await call('app_line_done', { p_secret: secret, p_kind: 'notif', p_ref: key, p_sent: sent, p_failed: failed, p_detail: detail || null });
    return json({ ok: true, sent, failed });
  }
  if (cmd === 'menu_clear') {
    const sub = String(body.sub || '');
    if (!/^U[0-9a-f]{32}$/.test(sub)) return json({ ok: false, reason: 'sub' }, 400);
    const r = await lineCall(deps, API, '/v2/bot/user/' + sub + '/richmenu', { method: 'DELETE' });
    return json({ ok: true, status: r.status });
  }
  if (cmd === 'setup') {
    const r = await setupMenus(deps, secret);
    await call('app_line_done', { p_secret: secret, p_kind: 'setup', p_ref: null, p_sent: 0, p_failed: r.ok ? 0 : 1, p_detail: r.detail });
    return json({ ok: r.ok, detail: r.detail });
  }
  if (cmd === 'ping') {
    const bits: string[] = [];
    const info = await lineCall(deps, API, '/v2/bot/info', { method: 'GET' });
    bits.push('bot ' + info.status + (info.data && info.data.basicId ? ' ' + info.data.basicId : ''));
    const q = await lineCall(deps, API, '/v2/bot/message/quota', { method: 'GET' });
    bits.push('quota ' + q.status + (q.data && q.data.value !== undefined ? ' ' + q.data.type + ':' + q.data.value : ''));
    const used = await lineCall(deps, API, '/v2/bot/message/quota/consumption', { method: 'GET' });
    bits.push('used ' + used.status + (used.data && used.data.totalUsage !== undefined ? ' ' + used.data.totalUsage : ''));
    const wh = await lineCall(deps, API, '/v2/bot/channel/webhook/endpoint', { method: 'GET' });
    bits.push('webhook ' + wh.status + (wh.data && wh.data.endpoint ? ' ' + (wh.data.active ? 'on ' : 'off ') + wh.data.endpoint : ''));
    bits.push('secrets ' + (envOf(deps, 'LINE_CHANNEL_SECRET') ? 'secret ' : 'NO-secret ') + (envOf(deps, 'LINE_CHANNEL_ACCESS_TOKEN') ? 'token ' : 'NO-token ') + (envOf(deps, 'DB_SECRET') ? 'db' : 'NO-db'));
    const okAll = info.status === 200 && q.status === 200 && wh.status === 200;
    await call('app_line_done', { p_secret: secret, p_kind: 'ping', p_ref: null, p_sent: 0, p_failed: okAll ? 0 : 1, p_detail: bits.join('; ') });
    return json({ ok: okAll, detail: bits.join('; ') });
  }
  return json({ ok: false, reason: 'cmd' }, 400);
}

async function onBrowser(deps: any, body: any, cors: Record<string, string>): Promise<Response> {
  const call = (deps && deps.rpc) || rpc;
  const secret = envOf(deps, 'DB_SECRET');
  const cmd = String((body && body.cmd) || '');
  if (cmd !== 'login' && cmd !== 'link') return json({ ok: false, reason: 'cmd' }, 400, cors);
  if (!secret) return json({ ok: false, reason: 'not_configured' }, 503, cors);
  const who = await verifyIdToken(deps, String(body.idToken || ''));
  if (!who) return json({ ok: false, reason: 'idtoken' }, 401, cors);
  const friend = await isFriend(deps, who.sub);
  if (cmd === 'login') {
    const role = body.role === 'trainer' ? 'trainer' : body.role === 'customer' ? 'customer' : null;
    const r = await call('app_line_login', {
      p_secret: secret, p_sub: who.sub, p_name: who.name, p_role: role, p_create: body.create === true,
      p_friend: friend, p_dev: String(body.dev || 'line').slice(0, 80),
    });
    if (r.status === 429) return json({ ok: false, reason: 'rate_limited' }, 429, cors);
    if (r.status === 403 || r.status === 401) return json({ ok: false, reason: 'not_configured' }, 503, cors);
    if (r.status !== 200 || !r.data) return json({ ok: false, reason: 'database', status: r.status }, 502, cors);
    if (r.data.ok) await Promise.race([setPersonalMenu(deps, secret, who.sub, String(r.data.role), friend), new Promise((res) => setTimeout(res, 2500))]);
    return json({ ...r.data, lineName: who.name, picture: who.picture }, 200, cors);
  }
  // link: the person is already signed in with their phone / password / Google; body.token is that sign-in
  const token = String(body.token || '');
  if (token.length < 40 || token.length > 200) return json({ ok: false, reason: 'unauthenticated' }, 401, cors);
  const r = await call('app_line_link', { p_secret: secret, p_token: token, p_sub: who.sub, p_name: who.name, p_friend: friend });
  if (r.status === 401) return json({ ok: false, reason: 'unauthenticated' }, 401, cors);
  if (r.status === 429) return json({ ok: false, reason: 'rate_limited' }, 429, cors);
  if (r.status === 403) return json({ ok: false, reason: 'not_configured' }, 503, cors);
  if (r.status !== 200 || !r.data) return json({ ok: false, reason: 'database', status: r.status }, 502, cors);
  if (r.data.ok) await Promise.race([setPersonalMenu(deps, secret, who.sub, String(r.data.role), friend), new Promise((res) => setTimeout(res, 2500))]);
  return json({ ...r.data, lineName: who.name, picture: who.picture, friend }, 200, cors);
}

/* `deps` lets the tests swap the network and the secrets. */
export async function handle(req: Request, deps?: any): Promise<Response> {
  const origin = req.headers.get('origin');
  const okOrigin = !!origin && allowedOrigins(deps).includes(origin);
  const cors: Record<string, string> = okOrigin ? {
    'Access-Control-Allow-Origin': origin as string, Vary: 'Origin',
    'Access-Control-Allow-Headers': 'content-type, authorization, apikey, x-client-info', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Max-Age': '600',
  } : {};
  if (req.method === 'OPTIONS') return okOrigin ? new Response(null, { status: 204, headers: cors }) : json({ ok: false, reason: 'origin' }, 403);
  if (req.method === 'GET') return json({ ok: true, service: 'trainkub-line' });
  if (req.method !== 'POST') return json({ ok: false, reason: 'method' }, 405);

  const raw = await req.text();
  if (raw.length > 200000) return json({ ok: false, reason: 'size' }, 413);
  const sig = req.headers.get('x-line-signature');
  if (sig) return onWebhook(deps, raw, sig);

  let body: any = {};
  try { body = JSON.parse(raw); } catch (_e) { /* no body */ }
  const secret = req.headers.get('x-push-secret') || '';
  if (secret) {
    const mine = envOf(deps, 'DB_SECRET');
    if (mine && !same(mine, secret)) return json({ ok: false, reason: 'unauthorized' }, 401);
    return onDatabase(deps, body, secret);
  }
  if (!okOrigin) return json({ ok: false, reason: 'origin' }, 403);
  return onBrowser(deps, body, cors);
}

if (typeof Deno !== 'undefined' && (Deno as any).serve) {
  (Deno as any).serve((req: Request) => handle(req).catch((e) => json({ ok: false, reason: 'error', message: String((e && e.message) || e).slice(0, 200) }, 500)));
}
