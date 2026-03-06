export const prerender = false;

import type { APIRoute } from 'astro';
import { queryDns, getRecordTypeName, VALID_TYPES } from '../../lib/dns-client';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();
  const type = (url.searchParams.get('type') || 'A').trim().toUpperCase();

  if (!domain) {
    return json({ error: 'El parámetro "domain" es requerido.' }, 400);
  }

  if (!DOMAIN_RE.test(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  if (!VALID_TYPES.includes(type)) {
    return json({ error: `Tipo no soportado. Válidos: ${VALID_TYPES.join(', ')}` }, 400);
  }

  try {
    const start = Date.now();
    const data = await queryDns(domain, type);
    const queryTime = Date.now() - start;

    const records = (data.Answer || []).map((r) => ({
      name: r.name,
      type: getRecordTypeName(r.type),
      TTL: r.TTL,
      data: r.data,
    }));

    return json({ domain, type, records, queryTime });
  } catch (err: any) {
    return json({ error: err.message || 'Error al consultar DNS.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
