import { queryDns } from './dns-client';

const DNSBLS = [
  'zen.spamhaus.org',
  'bl.spamcop.net',
  'b.barracudacentral.org',
  'dnsbl.sorbs.net',
  'spam.dnsbl.sorbs.net',
  'cbl.abuseat.org',
  'dnsbl-1.uceprotect.net',
  'psbl.surriel.com',
  'all.s5h.net',
  'dyna.spamrats.com',
  'access.redhawk.org',
  'rbl.interserver.net',
];

export interface BlacklistResult {
  list: string;
  listed: boolean;
  response?: string;
}

export interface BlacklistReport {
  ip: string;
  domain?: string;
  total: number;
  listed: number;
  clean: number;
  results: BlacklistResult[];
}

const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function reverseIp(ip: string): string {
  return ip.split('.').reverse().join('.');
}

async function checkDnsbl(ip: string, dnsbl: string): Promise<BlacklistResult> {
  const reversed = reverseIp(ip);
  const query = `${reversed}.${dnsbl}`;

  try {
    const res = await queryDns(query, 'A');
    if (res.Answer && res.Answer.length > 0) {
      return { list: dnsbl, listed: true, response: res.Answer[0].data };
    }
    return { list: dnsbl, listed: false };
  } catch {
    return { list: dnsbl, listed: false };
  }
}

export async function checkBlacklists(target: string): Promise<BlacklistReport> {
  let ip = target;
  let domain: string | undefined;

  if (!IP_RE.test(target)) {
    domain = target;
    const res = await queryDns(target, 'A');
    if (!res.Answer || res.Answer.length === 0) {
      throw new Error(`No se pudo resolver la IP de ${target}.`);
    }
    ip = res.Answer[0].data;
  }

  const settled = await Promise.allSettled(
    DNSBLS.map((dnsbl) => checkDnsbl(ip, dnsbl))
  );

  const results: BlacklistResult[] = settled.map((s) =>
    s.status === 'fulfilled' ? s.value : { list: '', listed: false }
  ).filter((r) => r.list !== '');

  const listed = results.filter((r) => r.listed).length;

  return {
    ip,
    domain,
    total: results.length,
    listed,
    clean: results.length - listed,
    results,
  };
}
