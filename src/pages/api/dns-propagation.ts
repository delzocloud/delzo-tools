export const prerender = false;

import type { APIRoute } from 'astro';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { checkPropagation, VALID_PROPAGATION_TYPES } from '../../lib/dns-propagation';


export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();
  const type = (url.searchParams.get('type') || 'A').trim().toUpperCase();

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!normalizeDomain(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  if (!VALID_PROPAGATION_TYPES.includes(type)) {
    return json({ error: `Tipo no soportado. Válidos: ${VALID_PROPAGATION_TYPES.join(', ')}` }, 400);
  }

  try {
    const report = await checkPropagation(domain, type);
    return json(report);
  } catch (err) {
    return json({ error: publicError(err, 'Error al verificar propagación.') }, 500);
  }
};

