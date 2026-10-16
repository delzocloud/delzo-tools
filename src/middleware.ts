import { defineMiddleware } from 'astro:middleware';

const ALLOWED_ORIGINS = new Set(['https://delzo.cloud', 'https://www.delzo.cloud', 'https://tools.delzo.cloud']);

// Matches current assets: Astro inline scripts, Google Fonts, Geist (jsDelivr),
// Leaflet (unpkg) + OpenStreetMap tiles, Google favicon service.
const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://unpkg.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://unpkg.com",
  "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net data:",
  "img-src 'self' data: blob: https://www.google.com https://*.gstatic.com https://*.tile.openstreetmap.org https://unpkg.com",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
  'upgrade-insecure-requests',
].join('; ');

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Security-Policy': CSP,
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
};


export const onRequest = defineMiddleware(async (context, next) => {
  // Prerendered pages are served as static assets: their headers come from public/_headers.
  if (context.isPrerendered) return next();
  const isApi = context.url.pathname.startsWith('/api/');
  const origin = context.request.headers.get('origin');
  const corsOk = isApi && origin !== null && ALLOWED_ORIGINS.has(origin);

  if (isApi && context.request.method === 'OPTIONS') {
    const h = new Headers({ Vary: 'Origin' });
    if (corsOk) {
      h.set('Access-Control-Allow-Origin', origin!);
      h.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
      h.set('Access-Control-Max-Age', '86400');
    }
    return new Response(null, { status: 204, headers: h });
  }

  const response = await next();
  // Responses from fetch() can be immutable; copy to be safe.
  const res = new Response(response.body, response);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) res.headers.set(k, v);
  if (isApi) {
    res.headers.delete('Access-Control-Allow-Origin');
    res.headers.append('Vary', 'Origin');
    if (corsOk) res.headers.set('Access-Control-Allow-Origin', origin!);
  }
  return res;
});
