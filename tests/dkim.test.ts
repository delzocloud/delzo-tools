import { describe, it, expect } from 'vitest';
import { analyzeDkim, analyzeSpf, analyzeDmarc, computeEmailScore, type TxtResolver } from '../src/lib/dns-parser';
import { probeOrder, providersFromSpf, providerFromCname, MAX_PROBES } from '../src/lib/dkim-selectors';

type Z = Record<string, { records: string[]; cnames?: string[] }>;
function zone(z: Z, log?: string[]): TxtResolver {
  return async (name) => {
    log?.push(name);
    const e = z[name];
    return { nxdomain: !e, records: e?.records ?? [], cnames: e?.cnames ?? [] };
  };
}
const KEY = 'v=DKIM1; k=rsa; p=MIIBIjANBg';

describe('DKIM probing', () => {
  it('tries google first and stops if found', async () => {
    const log: string[] = [];
    const r = await analyzeDkim('a.com', zone({ 'google._domainkey.a.com': { records: [KEY] } }, log));
    expect(r.status).toBe('pass');
    expect(r.selector).toBe('google');
    expect(r.provider).toBe('Google Workspace');
    expect(log[0]).toBe('google._domainkey.a.com');
    expect(log).toHaveLength(2); // google + wildcard check only
  });

  it('detects provider from the CNAME target', async () => {
    const r = await analyzeDkim('a.com', zone({ 's1._domainkey.a.com': { records: [KEY], cnames: ['s1.domainkey.u123.wl.sendgrid.net'] } }));
    expect(r.selector).toBe('s1');
    expect(r.provider).toBe('SendGrid');
  });

  it.each([
    ['selector1', 'Microsoft 365'],
    ['brevo1', 'Brevo (Sendinblue)'],
    ['mte1', 'Mailchimp Transactional (Mandrill)'],
    ['resend', 'Resend'],
    ['protonmail', 'Proton Mail'],
    ['fm1', 'Fastmail'],
    ['hostingermail-a', 'Hostinger'],
    ['zoho', 'Zoho Mail'],
    ['mailjet', 'Mailjet'],
  ])('finds %s (%s)', async (sel, prov) => {
    const r = await analyzeDkim('a.com', zone({ [`${sel}._domainkey.a.com`]: { records: [KEY] } }));
    expect(r.status).toBe('pass');
    expect(r.provider).toBe(prov);
  });

  it('SPF hints put the provider selectors first', () => {
    const order = probeOrder('v=spf1 include:mailgun.org ~all');
    expect(order.slice(0, 3)).toEqual(['pdk1', 'pdk2', 'k1']);
    expect(providersFromSpf('v=spf1 include:spf.protection.outlook.com -all')[0].provider).toBe('Microsoft 365');
    expect(providerFromCname(['selector1-x._domainkey.x.onmicrosoft.com'])).toBe('Microsoft 365');
  });

  it('respects the probe cap', async () => {
    const log: string[] = [];
    await analyzeDkim('a.com', zone({}, log));
    expect(log.length).toBeLessThanOrEqual(MAX_PROBES);
    const log2: string[] = [];
    await analyzeDkim('a.com', zone({}, log2), { maxProbes: 12 });
    expect(log2.length).toBeLessThanOrEqual(12);
  });

  it('unknown selector = unverified, no penalty (Gmail case)', async () => {
    const z = zone({
      'gmail.com': { records: ['v=spf1 redirect=_spf.google.com'] },
      '_spf.google.com': { records: ['v=spf1 include:_netblocks.google.com ~all'] },
      '_netblocks.google.com': { records: ['v=spf1 ip4:35.190.247.0/24 ~all'] },
      '_dmarc.gmail.com': { records: ['v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com'] },
      '20230601._domainkey.gmail.com': { records: [KEY] },
    });
    const spf = await analyzeSpf('gmail.com', z);
    const dmarc = await analyzeDmarc('gmail.com', z);
    const dkim = await analyzeDkim('gmail.com', z, { spfRecord: spf.record });
    expect(dkim.status).toBe('unverified');
    const sc = computeEmailScore(spf, dmarc, dkim);
    expect(sc.dkimScore).toBeNull();
    expect(sc.grade.grade).not.toBe('F');
    // With the real selector, it is verified
    const withSel = await analyzeDkim('gmail.com', z, { extraSelector: '20230601' });
    expect(withSel.status).toBe('pass');
  });

  it('only revoked keys = unverified (Hostinger rotation slots)', async () => {
    const r = await analyzeDkim('a.com', zone({ 'hostingermail-b._domainkey.a.com': { records: ['v=DKIM1; p='] } }));
    expect(r.status).toBe('unverified');
  });

  it('wildcard _domainkey = unverified', async () => {
    const wild: TxtResolver = async (n) => ({ nxdomain: false, records: n.endsWith('._domainkey.a.com') ? [KEY] : [] });
    const r = await analyzeDkim('a.com', wild);
    expect(r.wildcard).toBe(true);
    expect(r.status).toBe('unverified');
  });

  it('DNS failure = error', async () => {
    const r = await analyzeDkim('a.com', async () => { throw new Error('x'); });
    expect(r.status).toBe('error');
  });
});
