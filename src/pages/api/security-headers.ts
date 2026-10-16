export const prerender = false;

import type { APIRoute } from 'astro';
import { checkSecurityHeaders } from '../../lib/headers-checker';
import { json, publicError } from '../../lib/http';

export const GET: APIRoute = async ({ url }) => {
  const target = url.searchParams.get('url')?.trim();
  if (!target) return json({ error: 'Ingresá una URL o un dominio.' }, 400);
  try {
    return json(await checkSecurityHeaders(target));
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos conectarnos con el sitio.') }, 502);
  }
};
