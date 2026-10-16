/**
 * SSRF guard for tools that fetch user supplied URLs.
 * - only http/https, ports 80/443
 * - blocks private, loopback, link-local, CGNAT, metadata, multicast and
 *   documentation ranges (IPv4 and IPv6), both as literals and after DNS resolution
 * - follows redirects manually, re-validating every hop (max 5)
 * Residual risk: the runtime resolves the name again when fetching (DNS rebinding);
 * on Cloudflare Workers private ranges are not routable anyway.
 */
import { queryDns, answersOfType } from './dns-client';
import { USER_AGENT } from './http';

export class GuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GuardError';
  }
}

export const MAX_REDIRECTS = 5;

/* ---------------- IPv4 ---------------- */

export function parseIPv4(s: string): number | null {
  const m = s.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some((x) => x > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}

const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

export function isBlockedIPv4(ip: string): boolean {
  const n = parseIPv4(ip);
  if (n === null) return true; // not a valid v4: treat as unsafe
  return V4_BLOCKED.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((n & mask) >>> 0) === ((parseIPv4(base)! & mask) >>> 0);
  });
}

/* ---------------- IPv6 ---------------- */

/** Expands an IPv6 string into 8 16-bit groups, or null. Handles :: and embedded IPv4. */
export function parseIPv6(input: string): number[] | null {
  let s = input.replace(/^\[|\]$/g, '').split('%')[0].toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(s) || !s.includes(':')) return null;
  const v4 = s.match(/(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const n = parseIPv4(v4[1]);
    if (n === null) return null;
    s = s.slice(0, -v4[1].length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

export function isBlockedIPv6(ip: string): boolean {
  const g = parseIPv6(ip);
  if (!g) return true;
  const allZeroUntil = (n: number) => g.slice(0, n).every((x) => x === 0);
  if (allZeroUntil(8)) return true; // ::
  if (allZeroUntil(7) && g[7] === 1) return true; // ::1
  const embeddedV4 = () => `${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  if (allZeroUntil(5) && g[5] === 0xffff) return isBlockedIPv4(embeddedV4()); // ::ffff:a.b.c.d
  if (allZeroUntil(6)) return true; // deprecated ::a.b.c.d
  if (g[0] === 0x64 && g[1] === 0xff9b) return isBlockedIPv4(embeddedV4()); // NAT64
  if ((g[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0] & 0xffc0) === 0xfec0) return true; // fec0::/10 site-local
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  if (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) return true; // discard
  if (g[0] === 0x2002) return true; // 6to4 can embed private v4
  if (g[0] === 0x2001 && g[1] === 0) return true; // Teredo
  if (g[0] === 0xfd00 && g[1] === 0x0ec2) return true; // AWS IMDS v6 (covered by ULA, explicit)
  return false;
}

export function isBlockedIp(ip: string): boolean {
  return parseIPv4(ip) !== null ? isBlockedIPv4(ip) : isBlockedIPv6(ip);
}

/* ---------------- URL validation ---------------- */

const BLOCKED_HOST_RE = /(^|\.)(localhost|local|internal|intranet|lan|home|corp|localdomain|home\.arpa)$/i;

export type HostResolver = (host: string) => Promise<string[]>;

export const dohResolver: HostResolver = async (host) => {
  const [a, aaaa] = await Promise.all([queryDns(host, 'A'), queryDns(host, 'AAAA')]);
  return [...answersOfType(a, 'A'), ...answersOfType(aaaa, 'AAAA')].map((r) => r.data);
};

/** Parses and validates a URL string synchronously (no DNS). Returns the normalized URL. */
export function checkUrlSyntax(input: string): URL {
  let raw = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new GuardError('La URL no es válida.');
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new GuardError('Solo se pueden revisar direcciones http o https.');
  if (u.port && u.port !== '80' && u.port !== '443') throw new GuardError('Solo se permiten los puertos 80 y 443.');
  u.username = '';
  u.password = '';
  u.hash = '';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (parseIPv4(host) !== null || host.includes(':')) {
    if (isBlockedIp(host)) throw new GuardError('Esa dirección es privada o reservada y no se puede revisar.');
  } else {
    if (!host.includes('.') || BLOCKED_HOST_RE.test(host)) throw new GuardError('Ese nombre no es un dominio público.');
  }
  return u;
}

/** Full check: syntax plus DNS resolution of the hostname. */
export async function assertPublicUrl(input: string, resolve: HostResolver = dohResolver): Promise<URL> {
  const u = checkUrlSyntax(input);
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (parseIPv4(host) !== null || host.includes(':')) return u;
  let ips: string[];
  try {
    ips = await resolve(host);
  } catch {
    throw new GuardError('No pudimos resolver ese dominio. Revisá que esté bien escrito.');
  }
  if (ips.length === 0) throw new GuardError('Ese dominio no apunta a ningún servidor.');
  if (ips.some(isBlockedIp)) throw new GuardError('Ese dominio apunta a una dirección privada y no se puede revisar.');
  return u;
}

export interface Hop {
  url: string;
  status: number;
  headers: Headers;
  timing: number;
}

/**
 * fetch() with manual redirects; every hop is validated with assertPublicUrl.
 * Returns the final response plus every hop (final included).
 */
export async function safeFetch(
  input: string,
  opts: { method?: 'GET' | 'HEAD'; timeoutMs?: number; maxRedirects?: number; follow?: boolean; resolve?: HostResolver } = {},
): Promise<{ response: Response; hops: Hop[]; finalUrl: string }> {
  const { method = 'GET', timeoutMs = 10000, maxRedirects = MAX_REDIRECTS, follow = true, resolve = dohResolver } = opts;
  const hops: Hop[] = [];
  let current = (await assertPublicUrl(input, resolve)).toString();

  for (let i = 0; ; i++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const t0 = performance.now();
    let response: Response;
    try {
      response = await fetch(current, {
        method,
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
      });
    } catch (e: any) {
      if (e?.name === 'AbortError') throw new GuardError(`El sitio no respondió en ${Math.round(timeoutMs / 1000)} segundos.`);
      throw new GuardError('No pudimos conectarnos con el sitio. Revisá que la dirección esté bien y que el sitio esté online.');
    } finally {
      clearTimeout(timer);
    }
    hops.push({ url: current, status: response.status, headers: response.headers, timing: Math.round(performance.now() - t0) });

    const location = response.headers.get('location');
    if (!follow || response.status < 300 || response.status >= 400 || !location) {
      return { response, hops, finalUrl: current };
    }
    if (i >= maxRedirects) throw new GuardError(`Demasiadas redirecciones (más de ${maxRedirects}). Puede haber un bucle.`);
    let next: string;
    try {
      next = new URL(location, current).toString();
    } catch {
      throw new GuardError('El sitio redirige a una dirección inválida.');
    }
    current = (await assertPublicUrl(next, resolve)).toString();
    try { await response.body?.cancel(); } catch {}
  }
}
