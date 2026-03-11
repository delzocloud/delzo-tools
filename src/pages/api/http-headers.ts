export const prerender = false;

import type { APIRoute } from 'astro';

interface HeaderInfo {
  name: string;
  value: string;
  category: 'security' | 'cors' | 'caching' | 'server' | 'content' | 'other';
  description: string;
}

interface HeadersResult {
  url: string;
  finalUrl: string;
  status: number;
  statusText: string;
  timing: number;
  headers: HeaderInfo[];
  summary: {
    total: number;
    security: number;
    cors: number;
    caching: number;
    server: number;
    content: number;
    other: number;
  };
}

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
    const result = await fetchHeaders(normalized);
    return json(result);
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return json({ error: 'Timeout: el sitio no respondió en 15 segundos.' }, 504);
    }
    return json({ error: err.message || 'Error al obtener headers.' }, 500);
  }
};

async function fetchHeaders(targetUrl: string): Promise<HeadersResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  const startTime = performance.now();

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
      },
    });

    clearTimeout(timeout);
    const timing = Math.round(performance.now() - startTime);

    const headers: HeaderInfo[] = [];
    const summary = {
      total: 0,
      security: 0,
      cors: 0,
      caching: 0,
      server: 0,
      content: 0,
      other: 0,
    };

    response.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      const category = categorizeHeader(lowerKey);
      const description = getHeaderDescription(lowerKey);
      
      headers.push({
        name: key,
        value: value,
        category,
        description,
      });

      summary.total++;
      summary[category]++;
    });

    // Sort headers by category priority
    const categoryOrder = ['security', 'cors', 'caching', 'server', 'content', 'other'];
    headers.sort((a, b) => {
      const catDiff = categoryOrder.indexOf(a.category) - categoryOrder.indexOf(b.category);
      if (catDiff !== 0) return catDiff;
      return a.name.localeCompare(b.name);
    });

    return {
      url: targetUrl,
      finalUrl: response.url,
      status: response.status,
      statusText: getStatusText(response.status),
      timing,
      headers,
      summary,
    };

  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

function categorizeHeader(headerName: string): HeaderInfo['category'] {
  const securityHeaders = [
    'content-security-policy', 'csp', 'x-content-type-options', 'x-frame-options',
    'x-xss-protection', 'strict-transport-security', 'hsts', 'referrer-policy',
    'permissions-policy', 'cross-origin-embedder-policy', 'cross-origin-opener-policy',
    'cross-origin-resource-policy', 'origin-agent-cluster'
  ];
  
  const corsHeaders = [
    'access-control-allow-origin', 'access-control-allow-methods', 'access-control-allow-headers',
    'access-control-allow-credentials', 'access-control-max-age', 'access-control-expose-headers',
    'access-control-request-method', 'access-control-request-headers'
  ];
  
  const cacheHeaders = [
    'cache-control', 'expires', 'etag', 'last-modified', 'age', 'date',
    'pragma', 'vary'
  ];
  
  const serverHeaders = [
    'server', 'x-powered-by', 'via', 'x-cache', 'cf-ray', 'x-amz-cf-pop',
    'x-served-by', 'x-backend-server'
  ];

  if (securityHeaders.some(h => headerName.includes(h))) return 'security';
  if (corsHeaders.some(h => headerName.includes(h))) return 'cors';
  if (cacheHeaders.some(h => headerName.includes(h))) return 'caching';
  if (serverHeaders.some(h => headerName.includes(h))) return 'server';
  if (headerName.startsWith('content-')) return 'content';
  return 'other';
}

function getHeaderDescription(headerName: string): string {
  const descriptions: Record<string, string> = {
    'content-security-policy': 'Define fuentes permitidas para contenido',
    'strict-transport-security': 'Fuerza HTTPS (HSTS)',
    'x-content-type-options': 'Previene MIME sniffing',
    'x-frame-options': 'Controla si el sitio puede ser embebido',
    'x-xss-protection': 'Protección contra XSS (legacy)',
    'referrer-policy': 'Controla información enviada en Referer',
    'permissions-policy': 'Controla APIs del navegador disponibles',
    'access-control-allow-origin': 'Permite CORS desde origen especificado',
    'cache-control': 'Directivas de caching del navegador',
    'etag': 'Identificador de versión para caching',
    'last-modified': 'Fecha de última modificación del recurso',
    'server': 'Software servidor utilizado',
    'x-powered-by': 'Framework/tecnología utilizada',
    'content-type': 'Tipo MIME del contenido',
    'content-length': 'Tamaño del cuerpo en bytes',
    'content-encoding': 'Compresión aplicada (gzip, brotli)',
    'set-cookie': 'Cookies a establecer',
    'date': 'Fecha/hora del servidor',
  };
  
  return descriptions[headerName.toLowerCase()] || '';
}

function normalizeUrl(input: string): string | null {
  let url = input.trim();
  if (!url.match(/^https?:\/\//i)) {
    url = 'https://' + url;
  }
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    return parsed.toString();
  } catch {
    return null;
  }
}

function getStatusText(status: number): string {
  const texts: Record<number, string> = {
    200: 'OK',
    201: 'Created',
    204: 'No Content',
    301: 'Moved Permanently',
    302: 'Found',
    304: 'Not Modified',
    307: 'Temporary Redirect',
    308: 'Permanent Redirect',
    400: 'Bad Request',
    401: 'Unauthorized',
    403: 'Forbidden',
    404: 'Not Found',
    405: 'Method Not Allowed',
    500: 'Internal Server Error',
    502: 'Bad Gateway',
    503: 'Service Unavailable',
  };
  return texts[status] || 'Unknown';
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
