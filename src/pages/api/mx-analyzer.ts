export const prerender = false;

import type { APIRoute } from 'astro';
import { analyzeMx } from '../../lib/mx-analyzer';
import { json, normalizeDomain, publicError } from '../../lib/http';

export const GET: APIRoute = async ({ url }) => {
  const raw = url.searchParams.get('domain');
  if (!raw?.trim()) return json({ error: 'Ingresá un dominio.' }, 400);
  const domain = normalizeDomain(raw);
  if (!domain) return json({ error: 'Ese dominio no parece válido. Ejemplo: tuempresa.com.ar' }, 400);
  try {
    return json(await analyzeMx(domain));
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos analizar los servidores de correo.') }, 502);
  }
};
