import { queryDns } from './dns-client';

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
}

export interface MxReport {
  domain: string;
  mxRecords: MxRecord[];
  analysis: MxAnalysis;
}

const PROVIDERS: [RegExp, string][] = [
  [/\.(google\.com|googlemail\.com)\.?$/i, 'Google Workspace'],
  [/\.(outlook\.com|protection\.outlook\.com)\.?$/i, 'Microsoft 365'],
  [/\.pphosted\.com\.?$/i, 'Proofpoint'],
  [/\.mimecast\.com\.?$/i, 'Mimecast'],
  [/\.barracudanetworks\.com\.?$/i, 'Barracuda'],
  [/\.secureserver\.net\.?$/i, 'GoDaddy'],
  [/\.zoho\.com\.?$/i, 'Zoho'],
];

function detectProvider(hostname: string): string {
  for (const [re, name] of PROVIDERS) {
    if (re.test(hostname)) return name;
  }
  return 'Personalizado';
}

export async function analyzeMx(domain: string): Promise<MxReport> {
  const mxRes = await queryDns(domain, 'MX');

  if (!mxRes.Answer || mxRes.Answer.length === 0) {
    throw new Error(`No se encontraron registros MX para ${domain}.`);
  }

  const mxEntries = mxRes.Answer
    .filter((a) => a.type === 15)
    .map((a) => {
      const parts = a.data.split(' ');
      return {
        priority: parseInt(parts[0], 10),
        hostname: parts[1] || a.data,
      };
    })
    .sort((a, b) => a.priority - b.priority);

  const mxRecords: MxRecord[] = await Promise.all(
    mxEntries.map(async (mx) => {
      let ips: string[] = [];
      try {
        const aRes = await queryDns(mx.hostname.replace(/\.$/, ''), 'A');
        ips = (aRes.Answer || []).map((a) => a.data);
      } catch {}
      const provider = detectProvider(mx.hostname);
      return { priority: mx.priority, hostname: mx.hostname, ips, provider };
    })
  );

  const providers = [...new Set(mxRecords.map((r) => r.provider))];
  const mainProvider = providers.length === 1 ? providers[0] : 'Múltiples';
  const priorities = [...new Set(mxRecords.map((r) => r.priority))];
  const totalIps = mxRecords.reduce((sum, r) => sum + r.ips.length, 0);
  const hasRedundancy = mxRecords.length > 1 && (priorities.length > 1 || totalIps > 1);

  let details: string;
  if (mxRecords.length === 1) {
    details = 'Solo hay un servidor MX. Se recomienda agregar al menos uno de respaldo.';
  } else if (hasRedundancy) {
    details = `${mxRecords.length} servidores MX con ${priorities.length} nivel(es) de prioridad. Buena redundancia.`;
  } else {
    details = `${mxRecords.length} servidores MX pero con la misma prioridad. Considerá variar prioridades.`;
  }

  return {
    domain,
    mxRecords,
    analysis: {
      provider: mainProvider,
      hasRedundancy,
      details,
      totalMx: mxRecords.length,
    },
  };
}
