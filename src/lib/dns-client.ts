const DOH_URL = 'https://cloudflare-dns.com/dns-query';

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

export async function queryDns(domain: string, type: string): Promise<DohResponse> {
  const typeNum = RECORD_TYPES[type.toUpperCase()];
  if (!typeNum) {
    throw new Error(`Tipo de registro no soportado: ${type}`);
  }

  const url = `${DOH_URL}?name=${encodeURIComponent(domain)}&type=${typeNum}`;
  const res = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
  });

  if (!res.ok) {
    throw new Error(`Error en la consulta DNS (HTTP ${res.status})`);
  }

  return res.json();
}

export function getRecordTypeName(typeNum: number): string {
  for (const [name, num] of Object.entries(RECORD_TYPES)) {
    if (num === typeNum) return name;
  }
  return String(typeNum);
}

export const VALID_TYPES = Object.keys(RECORD_TYPES);
