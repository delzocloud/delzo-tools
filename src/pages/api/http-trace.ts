export const prerender = false;

import type { APIRoute } from 'astro';
import { json, publicError } from '../../lib/http';
import { safeFetch, MAX_REDIRECTS, GuardError, checkUrlSyntax, assertPublicUrl } from '../../lib/url-guard';


interface Hop {
  step: number;
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  timing: number;
}

const TIMEOUT_MS = 10000;

export const GET: APIRoute = async ({ url }) => {
  const targetUrl = url.searchParams.get('url')?.trim();
  if (!targetUrl) return json({ error: 'Ingresá una URL.' }, 400);

  try {
    checkUrlSyntax(targetUrl);
    const hops = await traceRedirects(targetUrl);
    return json({ hops, total: hops.length });
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos seguir las redirecciones.') }, 502);
  }
};

/** Same as safeFetch, but keeps every hop (also the one we refuse to follow) for display. */
async function traceRedirects(initialUrl: string): Promise<Hop[]> {
  const hops: Hop[] = [];
  let current = (await assertPublicUrl(initialUrl)).toString();
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const { response, hops: one } = await safeFetch(current, { method: 'HEAD', timeoutMs: TIMEOUT_MS, follow: false });
    const h = one[0];
    const headers: Record<string, string> = {};
    h.headers.forEach((v, k) => (headers[k.toLowerCase()] = v));
    hops.push({ step: hops.length + 1, url: h.url, status: h.status, statusText: getStatusText(h.status), headers, timing: h.timing });
    const location = response.headers.get('location');
    if (response.status < 300 || response.status >= 400 || !location) return hops;
    current = new URL(location, current).toString();
  }
  throw new GuardError(`Demasiadas redirecciones (más de ${MAX_REDIRECTS}). Puede haber un bucle.`);
}


function getStatusText(status: number): string {
  const texts: Record<number, string> = {
    200: 'OK', 201: 'Creado', 204: 'Sin contenido',
    300: 'Varias opciones', 301: 'Redirección permanente', 302: 'Redirección temporal', 303: 'Ver otra', 304: 'Sin cambios',
    307: 'Redirección temporal', 308: 'Redirección permanente',
    400: 'Pedido inválido', 401: 'Requiere login', 403: 'Prohibido', 404: 'No encontrado', 405: 'Método no permitido',
    500: 'Error del servidor', 502: 'Puerta de enlace con error', 503: 'Servicio no disponible', 504: 'Tiempo de espera agotado',
  };
  return texts[status] || `Código ${status}`;
}
