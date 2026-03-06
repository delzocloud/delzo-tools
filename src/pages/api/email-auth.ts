export const prerender = false;

import type { APIRoute } from 'astro';
import { analyzeSpf, analyzeDmarc, analyzeDkim } from '../../lib/dns-parser';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!DOMAIN_RE.test(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  try {
    const [spf, dmarc, dkim] = await Promise.all([
      analyzeSpf(domain),
      analyzeDmarc(domain),
      analyzeDkim(domain),
    ]);

    return json({ domain, spf, dmarc, dkim });
  } catch (err: any) {
    return json({ error: err.message || 'Error al analizar la autenticación de email.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
