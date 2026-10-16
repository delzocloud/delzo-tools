const DOH_URL = 'https://cloudflare-dns.com/dns-query';
export const DNS_TIMEOUT_MS = 5000;

const RECORD_TYPES: Record<string, number> = {
  A: 1, AAAA: 28, MX: 15, TXT: 16, CNAME: 5, NS: 2, SOA: 6, PTR: 12, SRV: 33,
};

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
  Authority?: DohAnswer[];
}

/** DNS RCODEs: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN, 5 REFUSED */
export const RCODE = { NOERROR: 0, SERVFAIL: 2, NXDOMAIN: 3, REFUSED: 5 } as const;

export class DnsError extends Error {
  constructor(message: string, public kind: 'timeout' | 'http' | 'servfail' | 'refused' | 'unsupported') {
    super(message);
    this.name = 'DnsError';
  }
}

export async function queryDns(domain: string, type: string, timeoutMs = DNS_TIMEOUT_MS): Promise<DohResponse> {
  const typeNum = RECORD_TYPES[type.toUpperCase()];
  if (!typeNum) throw new DnsError(`Tipo de registro no soportado: ${type}`, 'unsupported');

  const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${typeNum}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: controller.signal });
  } catch {
    throw new DnsError('El servidor DNS tardó demasiado en responder. Probá de nuevo en un rato.', 'timeout');
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) throw new DnsError('No pudimos consultar el DNS en este momento. Probá de nuevo en un rato.', 'http');

  const data = (await res.json()) as DohResponse;
  if (data.Status === RCODE.SERVFAIL) throw new DnsError('El DNS del dominio no respondió bien (SERVFAIL). Puede ser un problema temporal o de configuración.', 'servfail');
  if (data.Status === RCODE.REFUSED) throw new DnsError('El DNS del dominio rechazó la consulta.', 'refused');
  return data;
}

export function isNxDomain(r: DohResponse): boolean {
  return r.Status === RCODE.NXDOMAIN;
}

/** Answers of the requested type only (skips CNAME chain entries). */
export function answersOfType(r: DohResponse, type: string): DohAnswer[] {
  const t = RECORD_TYPES[type.toUpperCase()];
  return (r.Answer || []).filter((a) => a.type === t);
}

/**
 * Joins a TXT record that arrives split in several quoted strings
 * ("part1" "part2") into a single value, as RFC 7208 / 6376 require.
 */
export function joinTxt(data: string): string {
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!parts) return data.trim();
  return parts.map((p) => p.slice(1, -1).replace(/\\(["\\])/g, '$1')).join('');
}

export async function queryTxt(name: string): Promise<{ nxdomain: boolean; records: string[]; cnames?: string[] }> {
  const r = await queryDns(name, 'TXT');
  return {
    nxdomain: isNxDomain(r),
    records: answersOfType(r, 'TXT').map((a) => joinTxt(a.data)),
    cnames: answersOfType(r, 'CNAME').map((a) => a.data.replace(/\.$/, '').toLowerCase()),
  };
}

export function getRecordTypeName(typeNum: number): string {
  for (const [name, num] of Object.entries(RECORD_TYPES)) {
    if (num === typeNum) return name;
  }
  return String(typeNum);
}

export const VALID_TYPES = Object.keys(RECORD_TYPES);
