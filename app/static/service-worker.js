const CACHE_NAME = "mailergg-shell-v1";
const SHELL = [
  "/",
  "/login",
  "/static/styles.css",
  "/static/manifest.webmanifest",
  "/static/icon.svg"
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const { request } = event;
  if (request.method !== "GET") return;
  event.respondWith(fetch(request).catch(() => caches.match(request).then((cached) => cached || caches.match("/login"))));
});
