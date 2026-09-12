/* =====================================================================
   Service Worker — آموزش پزشکی در یک نگاه
   استراتژی: Cache First برای assets، Network First برای به‌روزرسانی
   ===================================================================== */

const CACHE_VERSION = 'med-edu-v3';
const CACHE_STATIC = CACHE_VERSION + '-static';
const CACHE_DYNAMIC = CACHE_VERSION + '-dynamic';

const STATIC_ASSETS = [
  './',
  './index.html',
  './manifest.json',
  './book-part1.js',
  './book-part2.js',
  './book-part3.js',
  './book-part4.js',
  './questions-part1.js',
  './questions-part2.js',
  './questions-part3.js',
  './questions-part4.js',
  './questions-part5.js'
];

// ===== Install =====
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_STATIC)
      .then(cache => cache.addAll(STATIC_ASSETS).catch(err => {
        console.warn('Some assets failed to cache:', err);
      }))
      .then(() => self.skipWaiting())
  );
});

// ===== Activate =====
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => !k.startsWith(CACHE_VERSION)).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ===== Fetch =====
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  // فقط درخواست‌های same-origin
  if (url.origin !== self.location.origin) return;

  // درخواست‌های API هرگز نباید کش شوند (داده‌های کاربر/ادمین همیشه باید زنده باشند)
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // HTML: Network First
  if (event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirst(event.request));
    return;
  }

  // سایر assets: Cache First
  event.respondWith(cacheFirst(event.request));
});

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const res = await fetch(request);
    if (res && res.status === 200 && res.type === 'basic') {
      const cache = await caches.open(CACHE_STATIC);
      cache.put(request, res.clone());
    }
    return res;
  } catch (err) {
    // fallback
    const fallback = await caches.match('./index.html');
    return fallback || new Response('Offline', { status: 503 });
  }
}

async function networkFirst(request) {
  try {
    const res = await fetch(request);
    if (res && res.status === 200 && res.type === 'basic') {
      const cache = await caches.open(CACHE_DYNAMIC);
      cache.put(request, res.clone());
    }
    return res;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    const fallback = await caches.match('./index.html');
    return fallback || new Response('Offline', { status: 503 });
  }
}

// پیام از کلاینت برای skipWaiting
self.addEventListener('message', event => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});