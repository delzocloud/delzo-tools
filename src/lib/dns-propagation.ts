interface Resolver {
  name: string;
  url: string;
  format: 'json' | 'wire';
}

const RESOLVERS: Resolver[] = [
  { name: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query', format: 'json' },
  { name: 'Google', url: 'https://dns.google/resolve', format: 'json' },
  { name: 'Quad9', url: 'https://dns.quad9.net/dns-query', format: 'wire' },
  { name: 'OpenDNS', url: 'https://doh.opendns.com/dns-query', format: 'wire' },
  { name: 'AdGuard', url: 'https://dns.adguard-dns.com/resolve', format: 'json' },
  { name: 'NextDNS', url: 'https://dns.nextdns.io/dns-query', format: 'json' },
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

// --- Wire format helpers (RFC 1035 / RFC 8484) ---

function buildDnsQuery(domain: string, typeNum: number): Uint8Array {
  const labels = domain.replace(/\.$/, '').split('.');
  // Header (12) + question (labels + null + type 2 + class 2)
  const nameLen = labels.reduce((sum, l) => sum + 1 + l.length, 0) + 1;
  const buf = new Uint8Array(12 + nameLen + 4);
  const view = new DataView(buf.buffer);

  // Header: ID=0, RD=1, QDCOUNT=1
  view.setUint16(2, 0x0100); // flags: RD=1
  view.setUint16(4, 1);      // QDCOUNT

  // Question: QNAME
  let offset = 12;
  for (const label of labels) {
    buf[offset++] = label.length;
    for (let i = 0; i < label.length; i++) {
      buf[offset++] = label.charCodeAt(i);
    }
  }
  buf[offset++] = 0; // null terminator

  // QTYPE and QCLASS
  view.setUint16(offset, typeNum);
  view.setUint16(offset + 2, 1); // IN class

  return buf;
}

function readName(buf: DataView, offset: number): [string, number] {
  const labels: string[] = [];
  let jumped = false;
  let returnOffset = offset;

  while (true) {
    if (offset >= buf.byteLength) break;
    const len = buf.getUint8(offset);
    if (len === 0) {
      if (!jumped) returnOffset = offset + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      // Pointer
      const ptr = ((len & 0x3f) << 8) | buf.getUint8(offset + 1);
      if (!jumped) returnOffset = offset + 2;
      offset = ptr;
      jumped = true;
      continue;
    }
    offset++;
    let label = '';
    for (let i = 0; i < len; i++) {
      label += String.fromCharCode(buf.getUint8(offset + i));
    }
    labels.push(label);
    offset += len;
    if (!jumped) returnOffset = offset;
  }

  return [labels.join('.'), returnOffset];
}

function ipv6ToString(buf: DataView, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 8; i++) {
    parts.push(buf.getUint16(offset + i * 2).toString(16));
  }
  // Compress longest run of zeros
  return parts.join(':').replace(/(^|:)0(:0)+(:|$)/, '$1::$3').replace(/^::$/, '::');
}

function parseDnsResponse(data: ArrayBuffer, queryType: number): string[] {
  const buf = new DataView(data);
  const ancount = buf.getUint16(6);

  // Skip header (12 bytes) + question section
  let offset = 12;
  // Skip QNAME
  while (offset < buf.byteLength) {
    const len = buf.getUint8(offset);
    if (len === 0) { offset++; break; }
    if ((len & 0xc0) === 0xc0) { offset += 2; break; }
    offset += 1 + len;
  }
  offset += 4; // QTYPE + QCLASS

  const answers: string[] = [];
  for (let i = 0; i < ancount && offset < buf.byteLength; i++) {
    // Read NAME
    const [, nextOffset] = readName(buf, offset);
    offset = nextOffset;

    const rtype = buf.getUint16(offset);
    const rdlength = buf.getUint16(offset + 8);
    offset += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

    if (rtype === queryType) {
      if (rtype === 1 && rdlength === 4) {
        // A record
        answers.push(`${buf.getUint8(offset)}.${buf.getUint8(offset + 1)}.${buf.getUint8(offset + 2)}.${buf.getUint8(offset + 3)}`);
      } else if (rtype === 28 && rdlength === 16) {
        // AAAA record
        answers.push(ipv6ToString(buf, offset));
      } else if (rtype === 15) {
        // MX record
        const priority = buf.getUint16(offset);
        const [exchange] = readName(buf, offset + 2);
        answers.push(`${priority} ${exchange}`);
      } else if (rtype === 16) {
        // TXT record
        let txt = '';
        let pos = offset;
        const end = offset + rdlength;
        while (pos < end) {
          const slen = buf.getUint8(pos);
          pos++;
          for (let j = 0; j < slen && pos < end; j++) {
            txt += String.fromCharCode(buf.getUint8(pos++));
          }
        }
        answers.push(txt);
      } else if (rtype === 5 || rtype === 2) {
        // CNAME or NS
        const [name] = readName(buf, offset);
        answers.push(name);
      }
    }
    offset += rdlength;
  }

  return answers.sort();
}

// Normalize a DNS answer string: strip surrounding quotes that some JSON
// resolvers add to TXT record data (e.g. `"v=spf1 ..."` → `v=spf1 ...`).
function normalizeAnswer(answer: string): string {
  return answer.replace(/^"(.*)"$/, '$1');
}

// --- Query functions ---

async function queryResolverJson(
  resolverName: string,
  resolverUrl: string,
  domain: string,
  typeNum: number,
  signal: AbortSignal,
): Promise<ResolverResult> {
  const url = `${resolverUrl}?name=${encodeURIComponent(domain)}&type=${typeNum}`;
  const start = Date.now();

  const res = await fetch(url, {
    headers: { Accept: 'application/dns-json' },
    signal,
  });
  const responseTime = Date.now() - start;

  if (!res.ok) {
    return { name: resolverName, answers: [], responseTime, status: 'error' };
  }

  const data = await res.json();
  const answers = (data.Answer || []).map((a: any) => normalizeAnswer(a.data as string)).sort();
  return { name: resolverName, answers, responseTime, status: 'ok' };
}

async function queryResolverWire(
  resolverName: string,
  resolverUrl: string,
  domain: string,
  typeNum: number,
  signal: AbortSignal,
): Promise<ResolverResult> {
  const query = buildDnsQuery(domain, typeNum);
  const start = Date.now();

  const res = await fetch(resolverUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/dns-message',
      Accept: 'application/dns-message',
    },
    body: query,
    signal,
  });
  const responseTime = Date.now() - start;

  if (!res.ok) {
    return { name: resolverName, answers: [], responseTime, status: 'error' };
  }

  const arrayBuf = await res.arrayBuffer();
  const answers = parseDnsResponse(arrayBuf, typeNum);
  return { name: resolverName, answers, responseTime, status: 'ok' };
}

async function queryResolver(
  resolver: Resolver,
  domain: string,
  type: string,
): Promise<ResolverResult> {
  const typeNum = RECORD_TYPES[type] || 1;

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const result = resolver.format === 'wire'
      ? await queryResolverWire(resolver.name, resolver.url, domain, typeNum, controller.signal)
      : await queryResolverJson(resolver.name, resolver.url, domain, typeNum, controller.signal);
    clearTimeout(timeout);
    return result;
  } catch (err: any) {
    clearTimeout(timeout);
    const responseTime = 0;
    const status = err.name === 'AbortError' ? 'timeout' : 'error';
    return { name: resolver.name, answers: [], responseTime, status };
  }
}

export async function checkPropagation(domain: string, type: string): Promise<PropagationReport> {
  const upperType = type.toUpperCase();
  if (!RECORD_TYPES[upperType]) {
    throw new Error(`Tipo no soportado. Válidos: ${Object.keys(RECORD_TYPES).join(', ')}`);
  }

  const settled = await Promise.allSettled(
    RESOLVERS.map((r) => queryResolver(r, domain, upperType))
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
