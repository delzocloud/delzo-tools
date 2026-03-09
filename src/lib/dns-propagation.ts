const RESOLVERS = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
  { name: 'Google', url: 'https://dns.google/resolve' },
  { name: 'AdGuard', url: 'https://dns.adguard-dns.com/resolve' },
  { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query' },
];

const RECORD_TYPES: Record<string, number> = {
  A: 1, AAAA: 28, MX: 15, TXT: 16, CNAME: 5, NS: 2,
};

export interface ResolverResult {
  name: string;
  answers: string[];
  responseTime: number;
  status: 'ok' | 'error' | 'timeout';
}

export interface PropagationReport {
  domain: string;
  type: string;
  resolvers: ResolverResult[];
  consistent: boolean;
}

async function queryResolver(
  resolverName: string,
  resolverUrl: string,
  domain: string,
  type: string,
): Promise<ResolverResult> {
  const typeNum = RECORD_TYPES[type] || 1;
  const url = `${resolverUrl}?name=${encodeURIComponent(domain)}&type=${typeNum}`;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  const start = Date.now();
  try {
    const res = await fetch(url, {
      headers: { Accept: 'application/dns-json' },
      signal: controller.signal,
    });
    clearTimeout(timeout);
    const responseTime = Date.now() - start;

    if (!res.ok) {
      return { name: resolverName, answers: [], responseTime, status: 'error' };
    }

    const data = await res.json();
    const answers = (data.Answer || []).map((a: any) => a.data as string).sort();

    return { name: resolverName, answers, responseTime, status: 'ok' };
  } catch (err: any) {
    clearTimeout(timeout);
    const responseTime = Date.now() - start;
    const status = err.name === 'AbortError' ? 'timeout' : 'error';
    return { name: resolverName, answers: [], responseTime, status };
  }
}

export async function checkPropagation(domain: string, type: string): Promise<PropagationReport> {
  const upperType = type.toUpperCase();
  if (!RECORD_TYPES[upperType]) {
    throw new Error(`Tipo no soportado. Válidos: ${Object.keys(RECORD_TYPES).join(', ')}`);
  }

  const settled = await Promise.allSettled(
    RESOLVERS.map((r) => queryResolver(r.name, r.url, domain, upperType))
  );

  const resolvers: ResolverResult[] = settled.map((s) =>
    s.status === 'fulfilled' ? s.value : { name: '?', answers: [], responseTime: 0, status: 'error' as const }
  );

  const okResolvers = resolvers.filter((r) => r.status === 'ok' && r.answers.length > 0);
  let consistent = true;
  if (okResolvers.length > 1) {
    const first = JSON.stringify(okResolvers[0].answers);
    consistent = okResolvers.every((r) => JSON.stringify(r.answers) === first);
  }

  return { domain, type: upperType, resolvers, consistent };
}

export const VALID_PROPAGATION_TYPES = Object.keys(RECORD_TYPES);
