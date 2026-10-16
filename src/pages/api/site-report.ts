export const prerender = false;

import type { APIRoute } from 'astro';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { analyzeSpf, analyzeDmarc, analyzeDkim, computeEmailScore } from '../../lib/dns-parser';
import { checkSecurityHeaders } from '../../lib/headers-checker';
import { fetchCertificates } from '../../lib/cert-checker';
import { queryDns, getRecordTypeName } from '../../lib/dns-client';
import { computeGrade } from '../../lib/grading';
import { domainExists, NXDOMAIN_MSG } from '../../lib/domain-check';


interface DnsRecords {
  a: { name: string; type: string; TTL: number; data: string }[];
  mx: { name: string; type: string; TTL: number; data: string }[];
  ns: { name: string; type: string; TTL: number; data: string }[];
  txt: { name: string; type: string; TTL: number; data: string }[];
}

export const GET: APIRoute = async ({ url }) => {
  const domain = normalizeDomain(url.searchParams.get('domain'));

  if (!domain) {
    return json({ error: 'Ingresá un dominio válido. Ejemplo: tuempresa.com.ar' }, 400);
  }

  try {
    if (!(await domainExists(domain))) return json({ error: NXDOMAIN_MSG, code: 'NXDOMAIN' }, 404);
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos consultar el DNS.') }, 502);
  }

  const errors: string[] = [];

  // Run all analyses in parallel
  const [emailResult, headersResult, dnsResult, certsResult] = await Promise.allSettled([
    // Email Security
    (async () => {
      const [spf, dmarc, dkim] = await Promise.all([
        analyzeSpf(domain),
        analyzeDmarc(domain),
        analyzeDkim(domain),
      ]);
      const score = computeEmailScore(spf, dmarc, dkim);
      return { domain, score, spf, dmarc, dkim };
    })(),

    // Security Headers
    checkSecurityHeaders(`https://${domain}`),

    // DNS Records
    (async (): Promise<DnsRecords> => {
      const [a, mx, ns, txt] = await Promise.all([
        queryDns(domain, 'A').then(d => (d.Answer || []).map(r => ({ name: r.name, type: getRecordTypeName(r.type), TTL: r.TTL, data: r.data }))),
        queryDns(domain, 'MX').then(d => (d.Answer || []).map(r => ({ name: r.name, type: getRecordTypeName(r.type), TTL: r.TTL, data: r.data }))),
        queryDns(domain, 'NS').then(d => (d.Answer || []).map(r => ({ name: r.name, type: getRecordTypeName(r.type), TTL: r.TTL, data: r.data }))),
        queryDns(domain, 'TXT').then(d => (d.Answer || []).map(r => ({ name: r.name, type: getRecordTypeName(r.type), TTL: r.TTL, data: r.data }))),
      ]);
      return { a, mx, ns, txt };
    })(),

    // Certificates
    fetchCertificates(domain, false),
  ]);

  // Extract results, tracking errors
  const emailSecurity = emailResult.status === 'fulfilled' ? emailResult.value : null;
  if (emailResult.status === 'rejected') errors.push(`Email: ${publicError(emailResult.reason, 'no se pudo revisar')}`);

  const securityHeaders = headersResult.status === 'fulfilled' ? headersResult.value : null;
  if (headersResult.status === 'rejected') errors.push(`Seguridad del sitio web: ${publicError(headersResult.reason, 'no se pudo revisar')}`);

  const dns = dnsResult.status === 'fulfilled' ? dnsResult.value : null;
  if (dnsResult.status === 'rejected') errors.push(`DNS: ${publicError(dnsResult.reason, 'no se pudo revisar')}`);

  const certificates = certsResult.status === 'fulfilled' ? certsResult.value : null;
  if (certsResult.status === 'rejected') errors.push(`Certificados: ${publicError(certsResult.reason, 'no se pudo revisar')}`);

  // Compute overall score (weighted average of email + headers)
  let overallTotal = 0;
  let weightCount = 0;

  if (emailSecurity) {
    overallTotal += emailSecurity.score.total * 0.5;
    weightCount += 0.5;
  }
  if (securityHeaders) {
    overallTotal += securityHeaders.score.total * 0.5;
    weightCount += 0.5;
  }

  const finalScore = weightCount > 0 ? Math.round(overallTotal / weightCount) : 0;
  const overallScore = {
    total: finalScore,
    grade: computeGrade(finalScore),
  };

  return json({
    domain,
    timestamp: new Date().toISOString(),
    overallScore,
    emailSecurity,
    securityHeaders,
    dns,
    certificates,
    errors,
  });
};

