export const prerender = false;

import type { APIRoute } from 'astro';
import { checkSecurityHeaders, normalizeUrl } from '../../lib/headers-checker';

export const GET: APIRoute = async ({ url }) => {
  let target = url.searchParams.get('url')?.trim();

  if (!target) {
    return json({ error: 'El parámetro "url" es requerido.' }, 400);
  }

  const normalized = normalizeUrl(target);
  if (!normalized) {
    return json({ error: 'URL o dominio inválido.' }, 400);
  }

  try {
    const result = await checkSecurityHeaders(normalized);
    return json(result);
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return json({ error: 'Timeout: el sitio no respondió en 10 segundos.' }, 504);
    }
    return json({ error: err.message || 'Error al conectar con el sitio.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
