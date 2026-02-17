const CACHE_VERSION = "maher-pwa-v5";
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const APP_SHELL = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./data/achievements.json",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable.png",
  "./assets/coachimg.jpg"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) => Promise.all(
      keys
        .filter((key) => !key.startsWith(CACHE_VERSION))
        .map((key) => caches.delete(key))
    )).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  if(event.request.method !== "GET") return;

  const url = new URL(event.request.url);

  if(event.request.mode === "navigate"){
    event.respondWith(
      fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put("./index.html", copy));
          return response;
        })
        .catch(() => caches.match("./index.html"))
    );
    return;
  }

  if(url.origin !== self.location.origin) return;
  if(url.pathname.startsWith("/api/")){
    event.respondWith(
      fetch(event.request).catch(() => new Response("", { status: 503, statusText: "Service Unavailable" }))
    );
    return;
  }

  event.respondWith(
    caches.match(event.request).then((cached) => {
      const networkFetch = fetch(event.request)
        .then((response) => {
          const copy = response.clone();
          caches.open(STATIC_CACHE).then((cache) => cache.put(event.request, copy));
          return response;
        })
        .catch(() => cached);

      return cached || networkFetch;
    })
  );
});
