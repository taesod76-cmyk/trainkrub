const CACHE_NAME = 'trainkrub-cache-v15';
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
          caches.open(CACHE_NAME).then((cache) => cache.put(request, copy));
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
