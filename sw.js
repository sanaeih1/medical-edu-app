/* =====================================================================
   Service Worker — آموزش پزشکی در یک نگاه
   استراتژی هوشمند: بدون نیاز به تغییر ورژن دستی
   - HTML و API: Network-First (همیشه تازه)
   - فایل‌های JS/CSS: Stale-While-Revalidate (سریع + آپدیت خودکار)
   ===================================================================== */

const CACHE_NAME = 'med-edu-runtime';

// ===== Install: بلافاصله فعال شو =====
self.addEventListener('install', event => {
  self.skipWaiting();
});

// ===== Activate: همه‌ی کش‌های قدیمی رو پاک کن =====
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ===== Fetch =====
self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  // API: همیشه از سرور، هرگز کش نشو
  if (url.pathname.startsWith('/api/')) {
    event.respondWith(fetch(event.request));
    return;
  }

  // HTML: Network-First (همیشه تازه، در آفلاین از کش)
  if (event.request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirst(event.request));
    return;
  }

  // سایر فایل‌ها (JS/CSS/تصاویر): Stale-While-Revalidate
  event.respondWith(staleWhileRevalidate(event.request));
});

async function networkFirst(request) {
  try {
    const res = await fetch(request);
    if (res && res.status === 200) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, res.clone());
    }
    return res;
  } catch (err) {
    const cached = await caches.match(request);
    return cached || new Response('Offline', { status: 503 });
  }
}

async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request)
    .then(res => {
      if (res && res.status === 200 && res.type === 'basic') {
        cache.put(request, res.clone());
      }
      return res;
    })
    .catch(() => cached);
  // اگه کش داشتیم، فوراً بده؛ در پس‌زمینه نسخه‌ی جدید بگیر
  return cached || fetchPromise;
}

// پیام از کلاینت برای فعال‌سازی فوری
self.addEventListener('message', event => {
  if (event.data === 'SKIP_WAITING') self.skipWaiting();
});
