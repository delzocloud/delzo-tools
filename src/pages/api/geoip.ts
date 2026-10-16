export const prerender = false;

import type { APIRoute } from 'astro';
import { json } from '../../lib/http';
import { parseIPv4, parseIPv6, isBlockedIp } from '../../lib/url-guard';

/**
 * Visitor IP: uses Cloudflare request.cf data (no third party).
 * Other IPs: ipwho.is over HTTPS (previously plain-HTTP ip-api.com).
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
    return geolocate(ip);
  }

  if (parseIPv4(ipParam) === null && parseIPv6(ipParam) === null) return json({ error: 'Esa IP no es válida.' }, 400);
  if (isBlockedIp(ipParam)) return json({ error: 'Esa IP es privada o reservada: no tiene ubicación pública.' }, 400);
  return geolocate(ipParam);
};

async function geolocate(ip: string) {
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(5000) });
    const d: any = await res.json();
    if (!d.success) return json({ error: 'No pudimos ubicar esa IP.' }, 400);
    return json({
      ip,
      country: d.country,
      countryCode: d.country_code,
      region: d.region,
      city: d.city,
      lat: d.latitude,
      lon: d.longitude,
      isp: d.connection?.isp,
      org: d.connection?.org,
      as: d.connection?.asn ? `AS${d.connection.asn}` : null,
      timezone: d.timezone?.id,
    });
  } catch {
    return json({ error: 'No pudimos consultar la ubicación. Probá de nuevo en un rato.' }, 502);
  }
}
