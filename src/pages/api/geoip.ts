export const prerender = false;

import type { APIRoute } from 'astro';

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

export const GET: APIRoute = async ({ url, request }) => {
  const ipParam = url.searchParams.get('ip')?.trim();

  // If no IP provided, try to detect visitor IP from headers
  if (!ipParam) {
    const cfIp = request.headers.get('cf-connecting-ip');
    const forwarded = request.headers.get('x-forwarded-for');
    const visitorIp = cfIp || forwarded?.split(',')[0]?.trim() || null;

    if (!visitorIp) {
      return json({ error: 'No se pudo detectar tu IP. Ingresá una manualmente.' }, 400);
    }

    return geolocate(visitorIp);
  }

  if (!IP_RE.test(ipParam) && !IPV6_RE.test(ipParam)) {
    return json({ error: 'IP inválida.' }, 400);
  }

  return geolocate(ipParam);
};

async function geolocate(ip: string) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone`);
    const data = await res.json();

    if (data.status === 'fail') {
      return json({ error: data.message || 'No se pudo geolocalizar la IP.' }, 400);
    }

    return json({
      ip,
      country: data.country,
      countryCode: data.countryCode,
      region: data.regionName,
      city: data.city,
      lat: data.lat,
      lon: data.lon,
      isp: data.isp,
      org: data.org,
      as: data.as,
      timezone: data.timezone,
    });
  } catch {
    return json({ error: 'Error al consultar la geolocalización.' }, 500);
  }
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
