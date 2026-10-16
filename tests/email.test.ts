import { describe, it, expect } from 'vitest';
import { joinTxt } from '../src/lib/dns-client';
import { parseSpf, analyzeSpf, analyzeDmarc, analyzeDkim, computeEmailScore, parseDkim, type TxtResolver } from '../src/lib/dns-parser';
import { organizationalDomain } from '../src/lib/psl';
import { normalizeDomain } from '../src/lib/http';

const zone = (records: Record<string, string[]>): TxtResolver => async (name) => ({
  nxdomain: !(name in records),
  records: records[name] ?? [],
});

describe('joinTxt', () => {
  it('joins multi-part strings', () => {
    expect(joinTxt('"v=DKIM1; p=ABC" "DEF"')).toBe('v=DKIM1; p=ABCDEF');
  });
  it('handles single and escaped quotes', () => {
    expect(joinTxt('"v=spf1 -all"')).toBe('v=spf1 -all');
    expect(joinTxt('"a\\"b"')).toBe('a"b');
  });
  it('returns raw data without quotes', () => {
    expect(joinTxt('v=spf1 ~all')).toBe('v=spf1 ~all');
  });
});

describe('parseSpf', () => {
  it('matches mechanisms exactly, case insensitive', () => {
    const p = parseSpf('V=SPF1 include:foo-all.com ip4:1.2.3.4 ~ALL');
    expect(p.all).toBe('~');
    expect(p.terms.map((t) => t.mechanism)).toEqual(['include', 'ip4', 'all']);
  });
  it('reads redirect and default qualifier', () => {
    const p = parseSpf('v=spf1 mx redirect=_spf.example.com');
    expect(p.redirect).toBe('_spf.example.com');
    expect(p.all).toBeNull();
    expect(p.terms[0].qualifier).toBe('+');
  });
});

describe('analyzeSpf', () => {
  it('flags multiple SPF records', async () => {
    const r = await analyzeSpf('a.com', zone({ 'a.com': ['v=spf1 -all', 'v=spf1 include:x ~all'] }));
    expect(r.status).toBe('fail');
    expect(r.records).toHaveLength(2);
  });
  it('follows redirect for the all qualifier', async () => {
    const r = await analyzeSpf('a.com', zone({ 'a.com': ['v=spf1 redirect=_spf.a.com'], '_spf.a.com': ['v=spf1 ip4:1.1.1.1 -all'] }));
    expect(r.allQualifier).toBe('-');
    expect(r.status).toBe('pass');
    expect(r.lookups).toBe(1);
  });
  it('counts lookups recursively and fails over 10', async () => {
    const recs: Record<string, string[]> = { 'a.com': ['v=spf1 include:i0.com include:i1.com ~all'] };
    for (let i = 0; i < 2; i++) recs[`i${i}.com`] = [`v=spf1 a mx include:j${i}.com ~all`];
    for (let i = 0; i < 2; i++) recs[`j${i}.com`] = ['v=spf1 a mx exists:x ptr ~all'];
    const r = await analyzeSpf('a.com', zone(recs));
    expect(r.lookups).toBeGreaterThan(10);
    expect(r.status).toBe('fail');
  });
  it('survives include loops', async () => {
    const r = await analyzeSpf('a.com', zone({ 'a.com': ['v=spf1 include:b.com ~all'], 'b.com': ['v=spf1 include:a.com ~all'] }));
    expect(r.status).toBe('warning');
    expect(r.details).toMatch(/bucle/);
  });
  it('treats +all as fail and missing record as fail', async () => {
    expect((await analyzeSpf('a.com', zone({ 'a.com': ['v=spf1 +all'] }))).status).toBe('fail');
    expect((await analyzeSpf('a.com', zone({ 'a.com': ['google-site-verification=x'] }))).status).toBe('fail');
  });
  it('reports DNS errors as error, not fail', async () => {
    const r = await analyzeSpf('a.com', async () => { const e = new Error('x'); e.name = 'DnsError'; throw e; });
    expect(r.status).toBe('error');
  });
});

describe('organizationalDomain', () => {
  it.each([
    ['mail.empresa.com.ar', 'empresa.com.ar'],
    ['a.b.municipio.gob.ar', 'municipio.gob.ar'],
    ['news.example.com', 'example.com'],
    ['example.com', 'example.com'],
    ['x.y.co.uk', 'y.co.uk'],
  ])('%s -> %s', (d, o) => expect(organizationalDomain(d)).toBe(o));
});

describe('analyzeDmarc', () => {
  it('falls back to organizational domain and uses sp=', async () => {
    const r = await analyzeDmarc('mail.empresa.com.ar', zone({ '_dmarc.empresa.com.ar': ['v=DMARC1; p=reject; sp=none; rua=mailto:a@b.c'] }));
    expect(r.inheritedFrom).toBe('empresa.com.ar');
    expect(r.effectivePolicy).toBe('none');
    expect(r.status).toBe('warning');
  });
  it('detects duplicates', async () => {
    const r = await analyzeDmarc('a.com', zone({ '_dmarc.a.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] }));
    expect(r.status).toBe('fail');
  });
  it('reads pct and is case insensitive', async () => {
    const r = await analyzeDmarc('a.com', zone({ '_dmarc.a.com': ['v=dmarc1; P=Quarantine; pct=50'] }));
    expect(r.policy).toBe('quarantine');
    expect(r.pct).toBe(50);
    expect(r.status).toBe('warning');
  });
});

describe('DKIM and score', () => {
  it('treats empty p= as revoked', () => {
    expect(parseDkim('v=DKIM1; k=rsa; p=')).toEqual({ valid: true, revoked: true });
    expect(parseDkim('v=DKIM1; p=MIIB')).toEqual({ valid: true, revoked: false });
  });
  it('finds brevo selector and scores reject above quarantine, no points without DKIM', async () => {
    const z = zone({
      'a.com': ['v=spf1 -all'],
      '_dmarc.a.com': ['v=DMARC1; p=reject; rua=mailto:x@a.com'],
      'brevo1._domainkey.a.com': ['v=DKIM1; p=MIIB'],
    });
    const spf = await analyzeSpf('a.com', z);
    const dkim = await analyzeDkim('a.com', z);
    expect(dkim.selector).toBe('brevo1');
    const reject = computeEmailScore(spf, await analyzeDmarc('a.com', z), dkim);
    const quarantine = computeEmailScore(spf, await analyzeDmarc('a.com', zone({ '_dmarc.a.com': ['v=DMARC1; p=quarantine; rua=mailto:x@a.com'] })), dkim);
    expect(reject.total).toBe(100);
    expect(reject.dmarcScore).toBeGreaterThan(quarantine.dmarcScore);
    const noDkim = await analyzeDkim('a.com', zone({}));
    expect(computeEmailScore(spf, await analyzeDmarc('a.com', z), noDkim).dkimScore).toBe(0);
  });
});

describe('normalizeDomain', () => {
  it.each([
    ['Ejemplo.COM', 'ejemplo.com'],
    ['https://ejemplo.com/path?x=1', 'ejemplo.com'],
    ['ñandú.com.ar', 'xn--and-6ma2c.com.ar'],
    ['localhost', null],
    ['<script>.com', null],
    ['a..com', null],
    ['1.2.3.4', null],
  ])('%s -> %s', (i, o) => expect(normalizeDomain(i)).toBe(o));
});
