/* Arcade Tracker service worker.
 *
 * Served from /static/, so its scope is /static/: it never sees an app page, only the
 * assets those pages load. It exists so the home-screen app has its icons and stylesheets
 * when the barcade Wi-Fi drops.
 *
 * Network first: a fresh copy always wins, and the cache is only a fallback. (v1 was cache
 * first, which would have kept serving the old stylesheet forever.) Bump CACHE_NAME when
 * this file's behaviour changes; activation deletes every other cache.
 */
const CACHE_NAME = "arcade-tracker-v2";
const PRECACHE = ["/static/icon-192.png", "/static/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (event.request.method !== "GET" || !url.pathname.startsWith("/static/")) return;
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response.ok) {
          const copy = response.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
