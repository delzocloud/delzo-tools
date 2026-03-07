export interface CrtShEntry {
  id: number;
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  serial_number: string;
  not_before: string;
  not_after: string;
}

export interface CertEntry {
  id: number;
  commonName: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  sans: string[];
  serialNumber: string;
  status: 'valid' | 'expiring' | 'expired';
}

export interface CertsResult {
  domain: string;
  total: number;
  certs: CertEntry[];
}

export async function fetchCertificates(domain: string, includeExpired: boolean): Promise<CertsResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);

  const crtUrl = `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`;
  const res = await fetch(crtUrl, {
    signal: controller.signal,
    headers: { 'User-Agent': 'DelzoCloud-CertMonitor/1.0' },
  });

  clearTimeout(timeout);

  if (!res.ok) {
    throw new Error('Error al consultar crt.sh.');
  }

  const raw: CrtShEntry[] = await res.json();

  const seen = new Set<string>();
  const now = new Date();
  const thirtyDays = 30 * 24 * 60 * 60 * 1000;
  const certs: CertEntry[] = [];

  for (const entry of raw) {
    if (seen.has(entry.serial_number)) continue;
    seen.add(entry.serial_number);

    const notAfter = new Date(entry.not_after);
    const notBefore = new Date(entry.not_before);

    let status: CertEntry['status'] = 'valid';
    if (notAfter < now) {
      status = 'expired';
    } else if (notAfter.getTime() - now.getTime() < thirtyDays) {
      status = 'expiring';
    }

    if (!includeExpired && status === 'expired') continue;

    const sans = entry.name_value
      ? entry.name_value.split('\n').map(s => s.trim()).filter(Boolean)
      : [];

    certs.push({
      id: entry.id,
      commonName: entry.common_name,
      issuer: entry.issuer_name,
      notBefore: notBefore.toISOString(),
      notAfter: notAfter.toISOString(),
      sans,
      serialNumber: entry.serial_number,
      status,
    });

    if (certs.length >= 50) break;
  }

  return { domain, total: certs.length, certs };
}
