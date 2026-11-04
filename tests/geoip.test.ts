import { describe, it, expect } from 'vitest';
import { lookupIp, parseIpGeolocation, parseIpWhoIs, geoErrorResponse, type Fetcher } from '../src/lib/geoip';

const IPGEO_BODY = {
  ip: '8.8.8.8',
  location: {
    country_name: 'United States',
    country_code2: 'US',
    state_prov: 'California',
    city: 'Mountain View',
    latitude: '37.42240',
    longitude: '-122.08421',
  },
  asn: { as_number: 'AS15169', organization: 'Google LLC' },
  time_zone: { name: 'America/Los_Angeles' },
};

const WHOIS_BODY = {
  success: true,
  country: 'United States',
  country_code: 'US',
  region: 'California',
  city: 'San Jose',
  latitude: 37.33,
  longitude: -121.89,
  connection: { asn: 15169, isp: 'Google LLC', org: 'Google LLC' },
  timezone: { id: 'America/Los_Angeles' },
};

type Route = { status: number; body?: unknown } | 'throw';

/** Fake fetch: routes by host, records every URL it was called with. */
function fakeFetch(routes: { ipgeo?: Route; whois?: Route }, calls: string[] = []): Fetcher {
  return async (input) => {
    calls.push(input);
    const route = input.includes('ipgeolocation.io') ? routes.ipgeo : routes.whois;
    if (!route) throw new Error(`unexpected fetch ${input}`);
    if (route === 'throw') throw new TypeError('network down');
    return new Response(route.body === undefined ? '' : JSON.stringify(route.body), { status: route.status });
  };
}

describe('parsers', () => {
  it('maps ipgeolocation.io v3 fields and converts string coordinates', () => {
    expect(parseIpGeolocation('8.8.8.8', IPGEO_BODY)).toEqual({
      ip: '8.8.8.8',
      country: 'United States',
      countryCode: 'US',
      region: 'California',
      city: 'Mountain View',
      lat: 37.4224,
      lon: -122.08421,
      isp: 'Google LLC',
      org: 'Google LLC',
      as: 'AS15169',
      timezone: 'America/Los_Angeles',
    });
  });

  it('returns null for an ipgeolocation body without location', () => {
    expect(parseIpGeolocation('1.2.3.4', { message: "'1.2.3.4' is a bogon IP address." })).toBeNull();
    expect(parseIpGeolocation('1.2.3.4', null)).toBeNull();
  });

  it('maps ipwho.is and numeric ASN', () => {
    expect(parseIpWhoIs('8.8.8.8', WHOIS_BODY)?.as).toBe('AS15169');
    expect(parseIpWhoIs('8.8.8.8', { success: false, message: 'Reserved range' })).toBeNull();
  });
});

describe('lookupIp', () => {
  it('uses ipgeolocation.io with the key and only the needed fields', async () => {
    const calls: string[] = [];
    const r = await lookupIp('8.8.8.8', 'k3y', fakeFetch({ ipgeo: { status: 200, body: IPGEO_BODY } }, calls));
    expect(r.kind).toBe('ok');
    expect(calls).toHaveLength(1);
    const u = new URL(calls[0]!);
    expect(u.pathname).toBe('/v3/ipgeo');
    expect(u.searchParams.get('apiKey')).toBe('k3y');
    expect(u.searchParams.get('ip')).toBe('8.8.8.8');
    expect(u.searchParams.get('fields')).toContain('location.latitude');
  });

  it('without a key goes straight to ipwho.is', async () => {
    const calls: string[] = [];
    const r = await lookupIp('8.8.8.8', undefined, fakeFetch({ whois: { status: 200, body: WHOIS_BODY } }, calls));
    expect(r.kind).toBe('ok');
    expect(calls).toEqual(['https://ipwho.is/8.8.8.8']);
  });

  it.each([
    ['quota exhausted', { status: 429 } as Route],
    ['invalid key', { status: 401 } as Route],
    ['outage', { status: 503 } as Route],
    ['network error', 'throw' as Route],
  ])('falls back to ipwho.is on %s', async (_label, ipgeo) => {
    const r = await lookupIp('8.8.8.8', 'k3y', fakeFetch({ ipgeo, whois: { status: 200, body: WHOIS_BODY } }));
    expect(r.kind).toBe('ok');
    if (r.kind === 'ok') expect(r.data.city).toBe('San Jose');
  });

  it('does not fall back when the IP simply has no location', async () => {
    const calls: string[] = [];
    const r = await lookupIp('8.8.8.8', 'k3y', fakeFetch({ ipgeo: { status: 400, body: { message: 'bogon' } } }, calls));
    expect(r.kind).toBe('not_found');
    expect(calls).toHaveLength(1);
  });

  it('reports the primary problem when the fallback also fails (the production bug)', async () => {
    const r = await lookupIp('8.8.8.8', 'k3y', fakeFetch({ ipgeo: { status: 429 }, whois: { status: 429 } }));
    expect(r.kind).toBe('rate_limited');
  });

  it('ipwho.is 429 without key is rate_limited, not "IP not found"', async () => {
    const r = await lookupIp('8.8.8.8', undefined, fakeFetch({ whois: { status: 429, body: { success: false } } }));
    expect(r.kind).toBe('rate_limited');
  });
});

describe('geoErrorResponse', () => {
  it('blames the service, not the IP, when rate limited', () => {
    expect(geoErrorResponse({ kind: 'rate_limited' })).toEqual({
      error: 'El servicio de ubicación está saturado. Probá de nuevo en un rato.',
      status: 503,
    });
    expect(geoErrorResponse({ kind: 'not_found' }).status).toBe(404);
  });
});
