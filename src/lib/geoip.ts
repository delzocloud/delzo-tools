/**
 * IP geolocation for user-supplied IPs.
 *
 * Primary: ipgeolocation.io (free plan, API key in the IPGEOLOCATION_API_KEY secret).
 * Fallback: ipwho.is (keyless). Its free quota is counted per source IP and the
 * shared Cloudflare egress IPs exhaust it daily, so it only helps in local dev or
 * when the key is missing or rejected.
 *
 * Kept free of `cloudflare:workers` imports so it can be unit tested.
 */

export interface GeoResult {
  readonly ip: string;
  readonly country: string | null;
  readonly countryCode: string | null;
  readonly region: string | null;
  readonly city: string | null;
  readonly lat: number | null;
  readonly lon: number | null;
  readonly isp: string | null;
  readonly org: string | null;
  readonly as: string | null;
  readonly timezone: string | null;
}

export type GeoOutcome =
  | { readonly kind: 'ok'; readonly data: GeoResult }
  /** The provider answered but has no location for this IP. */
  | { readonly kind: 'not_found' }
  /** Quota exhausted or rate limited. */
  | { readonly kind: 'rate_limited' }
  /** Key missing, invalid or plan problem: our configuration, not the user's input. */
  | { readonly kind: 'config' }
  /** Network error, timeout, 5xx or unexpected body. */
  | { readonly kind: 'unavailable' };

export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;

const IPGEO_FIELDS = [
  'ip',
  'location.country_name',
  'location.country_code2',
  'location.state_prov',
  'location.city',
  'location.latitude',
  'location.longitude',
  'asn.as_number',
  'asn.organization',
  'time_zone.name',
].join(',');

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

function num(v: unknown): number | null {
  const n = typeof v === 'number' ? v : typeof v === 'string' && v.trim() !== '' ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
}

function asLabel(v: unknown): string | null {
  if (typeof v === 'number' && Number.isInteger(v)) return `AS${v}`;
  const s = str(v);
  if (!s) return null;
  return /^AS/i.test(s) ? s.toUpperCase() : /^\d+$/.test(s) ? `AS${s}` : s;
}

/** Maps an ipgeolocation.io v3 body to our shape. Null if it carries no location at all. */
export function parseIpGeolocation(ip: string, body: unknown): GeoResult | null {
  if (!isRecord(body)) return null;
  const loc = isRecord(body.location) ? body.location : {};
  const asn = isRecord(body.asn) ? body.asn : {};
  const tz = isRecord(body.time_zone) ? body.time_zone : {};
  const result: GeoResult = {
    ip,
    country: str(loc.country_name),
    countryCode: str(loc.country_code2),
    region: str(loc.state_prov),
    city: str(loc.city),
    lat: num(loc.latitude),
    lon: num(loc.longitude),
    isp: str(asn.organization),
    org: str(asn.organization),
    as: asLabel(asn.as_number),
    timezone: str(tz.name),
  };
  return result.country === null && result.lat === null ? null : result;
}

/** Maps an ipwho.is body to our shape. Null when it reports failure. */
export function parseIpWhoIs(ip: string, body: unknown): GeoResult | null {
  if (!isRecord(body) || body.success !== true) return null;
  const conn = isRecord(body.connection) ? body.connection : {};
  const tz = isRecord(body.timezone) ? body.timezone : {};
  return {
    ip,
    country: str(body.country),
    countryCode: str(body.country_code),
    region: str(body.region),
    city: str(body.city),
    lat: num(body.latitude),
    lon: num(body.longitude),
    isp: str(conn.isp),
    org: str(conn.org),
    as: asLabel(conn.asn),
    timezone: str(tz.id),
  };
}

async function readJson(res: Response): Promise<unknown> {
  try {
    return await res.json();
  } catch {
    return null;
  }
}

export async function lookupIpGeolocation(ip: string, apiKey: string, fetcher: Fetcher = fetch): Promise<GeoOutcome> {
  const url = new URL('https://api.ipgeolocation.io/v3/ipgeo');
  url.searchParams.set('apiKey', apiKey);
  url.searchParams.set('ip', ip);
  url.searchParams.set('fields', IPGEO_FIELDS);
  let res: Response;
  try {
    res = await fetcher(url.toString(), { signal: AbortSignal.timeout(5000) });
  } catch {
    return { kind: 'unavailable' };
  }
  if (res.status === 429 || res.status === 423) return { kind: 'rate_limited' };
  if (res.status === 401 || res.status === 403) return { kind: 'config' };
  // Bogon, reserved or unknown IPs.
  if (res.status === 400 || res.status === 404) return { kind: 'not_found' };
  if (!res.ok) return { kind: 'unavailable' };
  const data = parseIpGeolocation(ip, await readJson(res));
  return data ? { kind: 'ok', data } : { kind: 'not_found' };
}

export async function lookupIpWhoIs(ip: string, fetcher: Fetcher = fetch): Promise<GeoOutcome> {
  let res: Response;
  try {
    res = await fetcher(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: AbortSignal.timeout(5000) });
  } catch {
    return { kind: 'unavailable' };
  }
  if (res.status === 429) return { kind: 'rate_limited' };
  if (!res.ok) return { kind: 'unavailable' };
  const data = parseIpWhoIs(ip, await readJson(res));
  return data ? { kind: 'ok', data } : { kind: 'not_found' };
}

/**
 * Primary provider first; falls back to ipwho.is only when the primary could not
 * answer for reasons that are not about the IP itself (no key, bad key, quota, outage).
 */
export async function lookupIp(ip: string, apiKey: string | undefined, fetcher: Fetcher = fetch): Promise<GeoOutcome> {
  if (apiKey) {
    const primary = await lookupIpGeolocation(ip, apiKey, fetcher);
    if (primary.kind === 'ok' || primary.kind === 'not_found') return primary;
    if (primary.kind === 'config') console.error('geoip: ipgeolocation.io rejected the API key');
    const fallback = await lookupIpWhoIs(ip, fetcher);
    // Report the primary problem if the fallback could not help either.
    return fallback.kind === 'ok' || fallback.kind === 'not_found' ? fallback : primary;
  }
  return lookupIpWhoIs(ip, fetcher);
}

/** Spanish message and HTTP status for every non-ok outcome. */
export function geoErrorResponse(outcome: Exclude<GeoOutcome, { kind: 'ok' }>): { readonly error: string; readonly status: number } {
  switch (outcome.kind) {
    case 'not_found':
      return { error: 'No encontramos una ubicación para esa IP.', status: 404 };
    case 'rate_limited':
      return { error: 'El servicio de ubicación está saturado. Probá de nuevo en un rato.', status: 503 };
    case 'config':
    case 'unavailable':
      return { error: 'No pudimos consultar la ubicación. Probá de nuevo en un rato.', status: 502 };
  }
}
