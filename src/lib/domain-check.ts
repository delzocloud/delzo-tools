import { queryDns, isNxDomain } from './dns-client';

/** true if the name exists in DNS (NOERROR, even without records of this type). */
export async function domainExists(domain: string): Promise<boolean> {
  const r = await queryDns(domain, 'SOA');
  return !isNxDomain(r);
}

export const NXDOMAIN_MSG = 'Ese dominio no existe. Revisá que esté bien escrito (por ejemplo: tuempresa.com.ar).';
