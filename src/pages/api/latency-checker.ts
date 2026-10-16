export const prerender = false;

import type { APIRoute } from 'astro';
import { json, publicError } from '../../lib/http';
import { safeFetch, checkUrlSyntax } from '../../lib/url-guard';

/**
 * Honest latency check: 3 real measurements from the single Cloudflare datacenter
 * that runs this request (no simulated regions).
 */
const MEASUREMENTS = 3;
const TIMEOUT_MS = 10000;

export const GET: APIRoute = async ({ url, request }) => {
  const targetUrl = url.searchParams.get('url')?.trim();
  if (!targetUrl) return json({ error: 'Ingresá una URL.' }, 400);

  const cf = (request as any).cf as { colo?: string; city?: string; country?: string } | undefined;

  try {
    checkUrlSyntax(targetUrl);
    const samples: { latency: number; status: number }[] = [];
    let finalUrl = targetUrl;
    for (let i = 0; i < MEASUREMENTS; i++) {
      const t0 = performance.now();
      const r = await safeFetch(targetUrl, { method: 'HEAD', timeoutMs: TIMEOUT_MS });
      samples.push({ latency: Math.round(performance.now() - t0), status: r.response.status });
      finalUrl = r.finalUrl;
      if (i < MEASUREMENTS - 1) await new Promise((res) => setTimeout(res, 100));
    }
    const sorted = samples.map((s) => s.latency).sort((a, b) => a - b);
    return json({
      url: finalUrl,
      origin: { colo: cf?.colo ?? null, country: cf?.country ?? null },
      samples,
      min: sorted[0],
      median: sorted[Math.floor(sorted.length / 2)],
      max: sorted[sorted.length - 1],
      note: 'Medición real desde un solo datacenter de Cloudflare (el más cercano a vos). Incluye redirecciones y la resolución DNS.',
    });
  } catch (err) {
    return json({ error: publicError(err, 'No pudimos medir la latencia. Revisá que el sitio esté online.') }, 502);
  }
};
