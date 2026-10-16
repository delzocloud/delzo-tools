export const prerender = false;

import type { APIRoute } from 'astro';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { fetchCertificates } from '../../lib/cert-checker';


export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();
  const includeExpired = url.searchParams.get('expired') === 'true';

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!normalizeDomain(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  try {
    const result = await fetchCertificates(domain, includeExpired);
    return json(result);
  } catch (err) {
    if (err.name === 'AbortError') {
      return json({ error: 'Timeout: crt.sh no respondió. Este servicio externo puede estar lento, intentá de nuevo en unos minutos.' }, 504);
    }
    return json({ error: publicError(err, 'Error al consultar certificados.') }, 500);
  }
};

