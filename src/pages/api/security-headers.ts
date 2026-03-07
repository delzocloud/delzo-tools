export const prerender = false;

import type { APIRoute } from 'astro';
import { computeGrade } from '../../lib/grading';

interface HeaderCheck {
  name: string;
  key: string;
  weight: number;
  value: string | null;
  status: 'pass' | 'warning' | 'fail';
  detail: string;
  score: number;
}

const URL_RE = /^https?:\/\/.+/;
const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

export const GET: APIRoute = async ({ url }) => {
  let target = url.searchParams.get('url')?.trim();

  if (!target) {
    return json({ error: 'El parámetro "url" es requerido.' }, 400);
  }

  // Auto-prepend https:// if bare domain
  if (!URL_RE.test(target)) {
    if (DOMAIN_RE.test(target)) {
      target = `https://${target}`;
    } else {
      return json({ error: 'URL o dominio inválido.' }, 400);
    }
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(target, {
      method: 'HEAD',
      signal: controller.signal,
      redirect: 'follow',
      headers: { 'User-Agent': 'DelzoCloud-SecurityHeaders/1.0' },
    });

    clearTimeout(timeout);

    const headers = res.headers;
    const checks: HeaderCheck[] = [];

    // 1. HSTS (25 pts)
    const hsts = headers.get('strict-transport-security');
    if (hsts) {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
      const sixMonths = 15768000;
      if (maxAge >= sixMonths) {
        checks.push({ name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 25, value: hsts, status: 'pass', detail: `max-age=${maxAge} (${Math.round(maxAge / 86400)} días)`, score: 25 });
      } else {
        checks.push({ name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 25, value: hsts, status: 'warning', detail: `max-age=${maxAge} — recomendado al menos 6 meses (${sixMonths}s)`, score: 13 });
      }
    } else {
      checks.push({ name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 25, value: null, status: 'fail', detail: 'Header no encontrado. Forzá HTTPS con HSTS.', score: 0 });
    }

    // 2. CSP (25 pts)
    const csp = headers.get('content-security-policy');
    if (csp) {
      checks.push({ name: 'Content-Security-Policy', key: 'content-security-policy', weight: 25, value: csp, status: 'pass', detail: 'CSP configurado.', score: 25 });
    } else {
      checks.push({ name: 'Content-Security-Policy', key: 'content-security-policy', weight: 25, value: null, status: 'fail', detail: 'Header no encontrado. CSP previene XSS y ataques de inyección.', score: 0 });
    }

    // 3. X-Content-Type-Options (15 pts)
    const xcto = headers.get('x-content-type-options');
    if (xcto) {
      checks.push({ name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 15, value: xcto, status: 'pass', detail: `Valor: ${xcto}`, score: 15 });
    } else {
      checks.push({ name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 15, value: null, status: 'fail', detail: 'Header no encontrado. Agregá "nosniff" para prevenir MIME sniffing.', score: 0 });
    }

    // 4. X-Frame-Options (10 pts)
    const xfo = headers.get('x-frame-options');
    if (xfo) {
      checks.push({ name: 'X-Frame-Options', key: 'x-frame-options', weight: 10, value: xfo, status: 'pass', detail: `Valor: ${xfo}`, score: 10 });
    } else {
      checks.push({ name: 'X-Frame-Options', key: 'x-frame-options', weight: 10, value: null, status: 'fail', detail: 'Header no encontrado. Previene clickjacking.', score: 0 });
    }

    // 5. Referrer-Policy (10 pts)
    const rp = headers.get('referrer-policy');
    if (rp) {
      checks.push({ name: 'Referrer-Policy', key: 'referrer-policy', weight: 10, value: rp, status: 'pass', detail: `Valor: ${rp}`, score: 10 });
    } else {
      checks.push({ name: 'Referrer-Policy', key: 'referrer-policy', weight: 10, value: null, status: 'fail', detail: 'Header no encontrado. Controlá qué info de referrer se envía.', score: 0 });
    }

    // 6. Permissions-Policy (10 pts)
    const pp = headers.get('permissions-policy');
    if (pp) {
      checks.push({ name: 'Permissions-Policy', key: 'permissions-policy', weight: 10, value: pp, status: 'pass', detail: 'Permissions-Policy configurado.', score: 10 });
    } else {
      checks.push({ name: 'Permissions-Policy', key: 'permissions-policy', weight: 10, value: null, status: 'fail', detail: 'Header no encontrado. Restringí acceso a APIs del navegador.', score: 0 });
    }

    // 7. X-XSS-Protection (5 pts)
    const xxss = headers.get('x-xss-protection');
    if (xxss) {
      checks.push({ name: 'X-XSS-Protection', key: 'x-xss-protection', weight: 5, value: xxss, status: 'pass', detail: `Valor: ${xxss}`, score: 5 });
    } else {
      checks.push({ name: 'X-XSS-Protection', key: 'x-xss-protection', weight: 5, value: null, status: 'warning', detail: 'Header no encontrado (deprecated — CSP lo reemplaza).', score: 3 });
    }

    const totalScore = checks.reduce((sum, c) => sum + c.score, 0);
    const grade = computeGrade(totalScore);

    return json({ url: target, score: { total: totalScore, grade }, headers: checks });
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
