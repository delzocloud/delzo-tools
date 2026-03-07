export const prerender = false;

import type { APIRoute } from 'astro';
import { fetchCertificates } from '../../lib/cert-checker';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const GET: APIRoute = async ({ url }) => {
  const domainsParam = url.searchParams.get('domains')?.trim();

  if (!domainsParam) {
    return json({ error: 'El parámetro "domains" es requerido.' }, 400);
  }

  const domains = domainsParam
    .split(',')
    .map((d) => d.trim().toLowerCase())
    .filter(Boolean)
    .slice(0, 10);

  if (domains.length === 0) {
    return json({ error: 'Ingresá al menos un dominio.' }, 400);
  }

  for (const d of domains) {
    if (!DOMAIN_RE.test(d)) {
      return json({ error: `Dominio inválido: ${d}` }, 400);
    }
  }

  try {
    const settled = await Promise.allSettled(
      domains.map((d) => fetchCertificates(d, false))
    );

    const now = new Date();
    const results = settled.map((s, i) => {
      if (s.status !== 'fulfilled' || s.value.certs.length === 0) {
        return {
          domain: domains[i],
          error: s.status === 'rejected' ? 'Error al consultar' : 'Sin certificados',
        };
      }

      const validCerts = s.value.certs.filter((c) => new Date(c.notAfter) > now);
      if (validCerts.length === 0) {
        return { domain: domains[i], error: 'Sin certificados vigentes' };
      }

      const nearest = validCerts.sort(
        (a, b) => new Date(a.notAfter).getTime() - new Date(b.notAfter).getTime()
      )[0];

      const daysLeft = Math.floor(
        (new Date(nearest.notAfter).getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
      );

      return {
        domain: domains[i],
        commonName: nearest.commonName,
        issuer: nearest.issuer,
        notAfter: nearest.notAfter,
        daysLeft,
        status: nearest.status,
      };
    });

    results.sort((a, b) => {
      if ('error' in a) return 1;
      if ('error' in b) return -1;
      return (a as any).daysLeft - (b as any).daysLeft;
    });

    return json({ total: domains.length, results });
  } catch (err: any) {
    return json({ error: err.message || 'Error al consultar certificados.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
