export const prerender = false;

import type { APIRoute } from 'astro';

interface Hop {
  step: number;
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  timing: number;
}

const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 15000;

export const GET: APIRoute = async ({ url }) => {
  const targetUrl = url.searchParams.get('url')?.trim();

  if (!targetUrl) {
    return json({ error: 'Ingresá una URL.' }, 400);
  }

  const normalized = normalizeUrl(targetUrl);
  if (!normalized) {
    return json({ error: 'URL inválida.' }, 400);
  }

  try {
    const hops = await traceRedirects(normalized);
    return json({ hops, total: hops.length });
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return json({ error: 'Timeout: el sitio no respondió en 15 segundos.' }, 504);
    }
    return json({ error: err.message || 'Error al seguir redirecciones.' }, 500);
  }
};

async function traceRedirects(initialUrl: string): Promise<Hop[]> {
  const hops: Hop[] = [];
  let currentUrl = initialUrl;
  let redirectCount = 0;

  while (redirectCount < MAX_REDIRECTS) {
    const startTime = performance.now();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);

    try {
      const response = await fetch(currentUrl, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (compatible; DelzoTools/1.0; +https://delzo.cloud)',
          'Accept': '*/*',
        },
      });

      clearTimeout(timeout);
      const timing = Math.round(performance.now() - startTime);

      const headers: Record<string, string> = {};
      response.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });

      hops.push({
        step: hops.length + 1,
        url: currentUrl,
        status: response.status,
        statusText: getStatusText(response.status),
        headers,
        timing,
      });

      // Check for redirects (300-399 status codes)
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) {
          currentUrl = resolveUrl(currentUrl, location);
          redirectCount++;
          continue;
        }
      }

      // Not a redirect, we're done
      break;

    } catch (err) {
      clearTimeout(timeout);
      throw err;
    }
  }

  if (redirectCount >= MAX_REDIRECTS) {
    throw new Error('Demasiadas redirecciones (máximo 10). Posible loop de redirección.');
  }

  return hops;
}

function normalizeUrl(input: string): string | null {
  let url = input.trim();

  // Add protocol if missing
  if (!url.match(/^https?:\/\//i)) {
    url = 'https://' + url;
  }

  try {
    const parsed = new URL(url);
    // Remove credentials if present
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return null;
  }
}

function resolveUrl(base: string, location: string): string {
  try {
    return new URL(location, base).toString();
  } catch {
    return location;
  }
}

function getStatusText(status: number): string {
  const texts: Record<number, string> = {
    300: 'Multiple Choices',
    301: 'Moved Permanently',
    302: 'Found',
    303: 'See Other',
    304: 'Not Modified',
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
    504: 'Gateway Timeout',
  };
  return texts[status] || 'Unknown';
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
