export const prerender = false;

import type { APIRoute } from 'astro';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { queryDns, getRecordTypeName, VALID_TYPES } from '../../lib/dns-client';


export const GET: APIRoute = async ({ url }) => {
  const domain = normalizeDomain(url.searchParams.get('domain'));
  const type = (url.searchParams.get('type') || 'A').trim().toUpperCase();

  if (!domain) {
    return json({ error: 'Ingresá un dominio válido. Ejemplo: tuempresa.com.ar' }, 400);
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
  } catch (err) {
    return json({ error: publicError(err, 'Error al consultar DNS.') }, 500);
  }
};

