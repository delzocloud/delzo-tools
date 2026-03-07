export const prerender = false;

import type { APIRoute } from 'astro';
import { analyzeSpf, analyzeDmarc, analyzeDkim, computeEmailScore } from '../../lib/dns-parser';
import { checkSecurityHeaders } from '../../lib/headers-checker';
import { fetchCertificates } from '../../lib/cert-checker';
import { queryDns, getRecordTypeName } from '../../lib/dns-client';
import { computeGrade } from '../../lib/grading';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

interface DnsRecords {
  a: { name: string; type: string; TTL: number; data: string }[];
  mx: { name: string; type: string; TTL: number; data: string }[];
  ns: { name: string; type: string; TTL: number; data: string }[];
  txt: { name: string; type: string; TTL: number; data: string }[];
}

export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!DOMAIN_RE.test(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
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
  if (emailResult.status === 'rejected') errors.push(`Email Security: ${emailResult.reason?.message || 'Error desconocido'}`);

  const securityHeaders = headersResult.status === 'fulfilled' ? headersResult.value : null;
  if (headersResult.status === 'rejected') errors.push(`Security Headers: ${headersResult.reason?.message || 'Error desconocido'}`);

  const dns = dnsResult.status === 'fulfilled' ? dnsResult.value : null;
  if (dnsResult.status === 'rejected') errors.push(`DNS: ${dnsResult.reason?.message || 'Error desconocido'}`);

  const certificates = certsResult.status === 'fulfilled' ? certsResult.value : null;
  if (certsResult.status === 'rejected') errors.push(`Certificados: ${certsResult.reason?.message || 'Error desconocido'}`);

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

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
