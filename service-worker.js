const CACHE_NAME = 'trainkrub-cache-v23';
const PRECACHE_URLS = [
  './',
  './index.html',
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './vendor/supabase-js-2.118.0.js'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(PRECACHE_URLS))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      )
    ).then(() => caches.open(CACHE_NAME)).then((cache) =>
      // drop any entry an earlier build stored under an address that still carried a #fragment
      cache.keys().then((reqs) => Promise.all(reqs.filter((r) => r.url.indexOf('#') >= 0).map((r) => cache.delete(r))))
    ).then(() => self.clients.claim())
  );
});

/* IMPORTANT: this worker must only ever touch files that belong to this site.
   Earlier versions also cached every cross-origin GET -- including the database
   (Supabase) replies -- and served them cache-first. That made each phone/computer
   keep showing the first answer it ever received (old account lists, old pending
   requests, "wrong password" for accounts that really existed). Anything that is not
   a same-origin file now goes straight to the network, untouched. */
self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Pages: network-first, falling back to the cached app shell when offline.
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          // keyed without the #fragment: after signing in with Google the address carries a short-lived token there
          caches.open(CACHE_NAME).then((cache) => cache.put(request.url.split('#')[0], copy));
          return response;
        })
        .catch(() => caches.match('./index.html'))
    );
    return;
  }

  // Versioned, rarely-changing files: cache-first.
  if (url.pathname.indexOf('/vendor/') >= 0 || url.pathname.indexOf('/icons/') >= 0) {
    event.respondWith(
      caches.match(request).then((cached) => cached || fetch(request).then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
        return response;
      }))
    );
    return;
  }

  // Everything else on this site (manifest, service-worker.js, ...): network-first.
  event.respondWith(
    fetch(request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
      return response;
    }).catch(() => caches.match(request))
  );
});

/* ---------------- pop-up notifications (Web Push) ----------------
   The server sends an encrypted message {title, body, tag, url}; this shows it as a system notification
   even when the app is closed. Tapping it opens the app on the notifications page. */
self.addEventListener('push', (event) => {
  let d = {};
  try { d = event.data ? event.data.json() : {}; }
  catch (e) { try { d = { body: event.data.text() }; } catch (e2) { d = {}; } }
  const title = String(d.title || 'เทรนครับ');
  const options = {
    body: String(d.body || ''),
    icon: 'icons/icon-192.png',
    badge: 'icons/badge-96.png',
    tag: d.tag ? String(d.tag) : undefined,
    data: { url: String(d.url || './?go=notif') },
    lang: 'th'
  };
  event.waitUntil((async () => {
    await self.registration.showNotification(title, options);
    // a window that is open right now refreshes itself so the bell and the lists are current
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    wins.forEach((c) => { try { c.postMessage({ type: 'tk-new' }); } catch (e) { /* ignore */ } });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = new URL((event.notification.data && event.notification.data.url) || './?go=notif', self.registration.scope).href;
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const c of wins) {
      if (c.url.indexOf(self.registration.scope) === 0) {
        try { await c.focus(); } catch (e) { /* ignore */ }
        try { c.postMessage({ type: 'tk-open', route: 'notif' }); } catch (e) { /* ignore */ }
        return;
      }
    }
    await self.clients.openWindow(target);
  })());
});
