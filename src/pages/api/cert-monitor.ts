export const prerender = false;

import type { APIRoute } from 'astro';
import { fetchCertificates } from '../../lib/cert-checker';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();
  const includeExpired = url.searchParams.get('expired') === 'true';

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!DOMAIN_RE.test(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  try {
    const result = await fetchCertificates(domain, includeExpired);
    return json(result);
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return json({ error: 'Timeout: crt.sh no respondió. Este servicio externo puede estar lento, intentá de nuevo en unos minutos.' }, 504);
    }
    return json({ error: err.message || 'Error al consultar certificados.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
