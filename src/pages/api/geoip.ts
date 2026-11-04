export const prerender = false;

import type { APIRoute } from 'astro';
import { getSecret } from 'astro:env/server';
import { json } from '../../lib/http';
import { parseIPv4, parseIPv6, isBlockedIp } from '../../lib/url-guard';
import { lookupIp, geoErrorResponse } from '../../lib/geoip';

/**
 * Visitor IP: uses Cloudflare request.cf data (no third party).
 * Other IPs: ipgeolocation.io (secret IPGEOLOCATION_API_KEY), ipwho.is as fallback.
 * See src/lib/geoip.ts.
 */
export const GET: APIRoute = async ({ url, request }) => {
  const ipParam = url.searchParams.get('ip')?.trim();

  if (!ipParam) {
    const ip = request.headers.get('cf-connecting-ip');
    const cf = (request as any).cf as Record<string, any> | undefined;
    if (!ip) return json({ error: 'No pudimos detectar tu IP. Ingresá una a mano.' }, 400);
    if (cf) {
      return json({
        ip,
        country: cf.country ?? null,
        countryCode: cf.country ?? null,
        region: cf.region ?? null,
        city: cf.city ?? null,
        lat: cf.latitude ? Number(cf.latitude) : null,
        lon: cf.longitude ? Number(cf.longitude) : null,
        isp: cf.asOrganization ?? null,
        org: cf.asOrganization ?? null,
        as: cf.asn ? `AS${cf.asn}` : null,
        timezone: cf.timezone ?? null,
      });
    }
    return geolocate(ip, request.url);
  }

  if (parseIPv4(ipParam) === null && parseIPv6(ipParam) === null) return json({ error: 'Esa IP no es válida.' }, 400);
  if (isBlockedIp(ipParam)) return json({ error: 'Esa IP es privada o reservada: no tiene ubicación pública.' }, 400);
  return geolocate(ipParam, request.url);
};

/** One day: an IP's location rarely changes, and each lookup spends free-plan quota. */
const CACHE_SECONDS = 86400;

/** Cloudflare's default cache (absent in plain Node, e.g. unit tests). */
function edgeCache(): Cache | null {
  const c: unknown = (globalThis as { caches?: unknown }).caches;
  if (typeof c === 'object' && c !== null && 'default' in c) return (c as { default: Cache }).default;
  return null;
}

async function geolocate(ip: string, requestUrl: string): Promise<Response> {
  // Cache key without the API key or any other query string: only the IP.
  const cacheKey = new Request(new URL(`/api/geoip/cache/${encodeURIComponent(ip.toLowerCase())}`, requestUrl).toString());
  const cache = edgeCache();
  const hit = await cache?.match(cacheKey).catch(() => undefined);
  if (hit) return json(await hit.json());

  const outcome = await lookupIp(ip, getSecret('IPGEOLOCATION_API_KEY'));
  if (outcome.kind !== 'ok') {
    const { error, status } = geoErrorResponse(outcome);
    return json({ error }, status);
  }
  // Store a copy for the edge cache; the client response keeps no-store.
  await cache
    ?.put(cacheKey, new Response(JSON.stringify(outcome.data), { headers: { 'Cache-Control': `public, max-age=${CACHE_SECONDS}` } }))
    .catch(() => undefined);
  return json(outcome.data);
}
