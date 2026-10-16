export const prerender = false;

import type { APIRoute } from 'astro';
import { analyzeSpf, analyzeDmarc, analyzeDkim, computeEmailScore } from '../../lib/dns-parser';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { domainExists, NXDOMAIN_MSG } from '../../lib/domain-check';

const SELECTOR_RE = /^[a-z0-9]([a-z0-9._-]{0,62})$/i;

export const GET: APIRoute = async ({ url }) => {
  const raw = url.searchParams.get('domain');
  if (!raw?.trim()) return json({ error: 'Ingresá un dominio.' }, 400);
  const domain = normalizeDomain(raw);
  if (!domain) return json({ error: 'Ese dominio no parece válido. Ejemplo: tuempresa.com.ar' }, 400);
  const selector = url.searchParams.get('selector')?.trim() || undefined;
  if (selector && !SELECTOR_RE.test(selector)) return json({ error: 'El selector DKIM no es válido.' }, 400);

  try {
    if (!(await domainExists(domain))) return json({ error: NXDOMAIN_MSG, code: 'NXDOMAIN' }, 404);
    const [spf, dmarc, dkim] = await Promise.all([
      analyzeSpf(domain),
      analyzeDmarc(domain),
      analyzeDkim(domain, undefined, selector),
    ]);
    const score = computeEmailScore(spf, dmarc, dkim);
    const incomplete = [spf, dmarc, dkim].some((r) => r.status === 'error');
    return json({ domain, score, incomplete, spf, dmarc, dkim });
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos analizar el dominio. Probá de nuevo en un rato.') }, 502);
  }
};
