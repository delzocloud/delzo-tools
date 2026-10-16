import { queryDns, answersOfType, isNxDomain, DnsError } from './dns-client';
import { NXDOMAIN_MSG } from './domain-check';

interface MxRecord {
  priority: number;
  hostname: string;
  ips: string[];
  provider: string;
}

interface MxAnalysis {
  provider: string;
  hasRedundancy: boolean;
  details: string;
  totalMx: number;
  nullMx: boolean;
}

export interface MxReport {
  domain: string;
  mxRecords: MxRecord[];
  analysis: MxAnalysis;
}

export const PROVIDERS: [RegExp, string][] = [
  [/(^|\.)(google\.com|googlemail\.com)\.?$/i, 'Google Workspace'],
  [/(^|\.)(outlook\.com|protection\.outlook\.com)\.?$/i, 'Microsoft 365'],
  [/(^|\.)mx\.cloudflare\.net\.?$/i, 'Cloudflare Email Routing'],
  [/(^|\.)pphosted\.com\.?$/i, 'Proofpoint'],
  [/(^|\.)mimecast\.com\.?$/i, 'Mimecast'],
  [/(^|\.)barracudanetworks\.com\.?$/i, 'Barracuda'],
  [/(^|\.)secureserver\.net\.?$/i, 'GoDaddy'],
  [/(^|\.)zoho\.(com|eu|in)\.?$/i, 'Zoho Mail'],
  [/(^|\.)(ferozo\.com|donweb\.com|dattamail\.com)\.?$/i, 'DonWeb / Ferozo'],
  [/(^|\.)hostinger\.(com|io)\.?$/i, 'Hostinger'],
  [/(^|\.)titan\.email\.?$/i, 'Titan Mail'],
  [/(^|\.)protonmail\.ch\.?$/i, 'Proton Mail'],
  [/(^|\.)icloud\.com\.?$/i, 'iCloud Mail'],
  [/(^|\.)yandex\.(net|ru)\.?$/i, 'Yandex'],
  [/(^|\.)mailgun\.org\.?$/i, 'Mailgun'],
  [/(^|\.)amazonaws\.com\.?$/i, 'Amazon SES'],
];

export function detectProvider(hostname: string): string {
  for (const [re, name] of PROVIDERS) {
    if (re.test(hostname)) return name;
  }
  return 'Otro / propio';
}

export function parseMx(data: string): { priority: number; hostname: string } {
  const [p, h] = data.trim().split(/\s+/);
  return { priority: parseInt(p, 10), hostname: h ?? '' };
}

export async function analyzeMx(domain: string): Promise<MxReport> {
  const mxRes = await queryDns(domain, 'MX');
  if (isNxDomain(mxRes)) throw new DnsError(NXDOMAIN_MSG, 'http');

  const entries = answersOfType(mxRes, 'MX').map((a) => parseMx(a.data)).sort((a, b) => a.priority - b.priority);

  if (entries.length === 0) {
    throw new DnsError(`${domain} no tiene servidores de correo (MX). Si querés recibir mails en este dominio, tenés que configurarlos con tu proveedor.`, 'http');
  }

  // RFC 7505 null MX: "0 ." means the domain explicitly does not receive mail.
  if (entries.length === 1 && (entries[0].hostname === '.' || entries[0].hostname === '')) {
    return {
      domain,
      mxRecords: [],
      analysis: { provider: 'Ninguno', hasRedundancy: false, totalMx: 0, nullMx: true, details: 'Este dominio declara que no recibe mails (null MX). Está bien si es a propósito.' },
    };
  }

  const mxRecords: MxRecord[] = await Promise.all(
    entries.map(async (mx) => {
      const host = mx.hostname.replace(/\.$/, '');
      let ips: string[] = [];
      try {
        const [a, aaaa] = await Promise.all([queryDns(host, 'A'), queryDns(host, 'AAAA')]);
        ips = [...answersOfType(a, 'A'), ...answersOfType(aaaa, 'AAAA')].map((r) => r.data);
      } catch {}
      return { priority: mx.priority, hostname: mx.hostname, ips, provider: detectProvider(host) };
    }),
  );

  const providers = [...new Set(mxRecords.map((r) => r.provider))];
  const mainProvider = providers.length === 1 ? providers[0] : 'Varios';
  const totalIps = mxRecords.reduce((sum, r) => sum + r.ips.length, 0);
  const hasRedundancy = mxRecords.length > 1 || totalIps > 1;
  const unresolved = mxRecords.filter((r) => r.ips.length === 0).map((r) => r.hostname);

  let details: string;
  if (mxRecords.length === 1 && totalIps > 1) {
    details = `Un servidor de correo con ${totalIps} direcciones IP: hay respaldo.`;
  } else if (mxRecords.length === 1) {
    details = 'Hay un solo servidor de correo sin respaldo. Si se cae, los mails pueden demorarse.';
  } else {
    details = `${mxRecords.length} servidores de correo. Hay respaldo si uno falla.`;
  }
  if (unresolved.length) details += ` Atención: ${unresolved.join(', ')} no apunta a ninguna IP.`;

  return { domain, mxRecords, analysis: { provider: mainProvider, hasRedundancy, details, totalMx: mxRecords.length, nullMx: false } };
}
