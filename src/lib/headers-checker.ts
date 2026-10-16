import { computeGrade, type GradeResult } from './grading';

export interface HeaderCheck {
  name: string;
  key: string;
  weight: number;
  value: string | null;
  status: 'pass' | 'warning' | 'fail';
  detail: string;
  score: number;
}

export interface HeadersResult {
  url: string;
  score: { total: number; grade: GradeResult };
  headers: HeaderCheck[];
}

import { safeFetch } from './url-guard';

export async function checkSecurityHeaders(target: string): Promise<HeadersResult> {
  // HEAD first; some servers answer 405/501 to HEAD, so fall back to GET.
  let { response, finalUrl } = await safeFetch(target, { method: 'HEAD', timeoutMs: 10000 });
  if (response.status === 405 || response.status === 501) {
    ({ response, finalUrl } = await safeFetch(target, { method: 'GET', timeoutMs: 10000 }));
    try { await response.body?.cancel(); } catch {}
  }
  const headers = response.headers;
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
      checks.push({ name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 25, value: hsts, status: 'warning', detail: `max-age=${maxAge}: recomendado al menos 6 meses (${sixMonths}s)`, score: 13 });
    }
  } else {
    checks.push({ name: 'Strict-Transport-Security', key: 'strict-transport-security', weight: 25, value: null, status: 'fail', detail: 'No está. HSTS obliga al navegador a usar siempre HTTPS.', score: 0 });
  }

  // 2. CSP (25 pts)
  const csp = headers.get('content-security-policy');
  if (csp) {
    const weak = /'unsafe-eval'|(^|[\s;])\*(\s|;|$)/.test(csp) || !/default-src|script-src/i.test(csp);
    checks.push({ name: 'Content-Security-Policy', key: 'content-security-policy', weight: 25, value: csp, status: weak ? 'warning' : 'pass', detail: weak ? 'Hay CSP pero es muy permisiva (comodines, unsafe-eval o sin default-src/script-src).' : 'CSP configurada: limita de dónde se puede cargar código.', score: weak ? 13 : 25 });
  } else {
    checks.push({ name: 'Content-Security-Policy', key: 'content-security-policy', weight: 25, value: null, status: 'fail', detail: 'No está. La CSP limita de dónde se puede cargar código y frena ataques de inyección.', score: 0 });
  }

  // 3. X-Content-Type-Options (15 pts)
  const xcto = headers.get('x-content-type-options');
  if (xcto) {
    checks.push({ name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 15, value: xcto, status: 'pass', detail: `Valor: ${xcto}`, score: 15 });
  } else {
    checks.push({ name: 'X-Content-Type-Options', key: 'x-content-type-options', weight: 15, value: null, status: 'fail', detail: 'No está. Agregá "nosniff" para que el navegador no adivine tipos de archivo.', score: 0 });
  }

  // 4. X-Frame-Options (10 pts)
  const xfo = headers.get('x-frame-options');
  const frameAncestors = csp && /frame-ancestors/i.test(csp);
  if (xfo || frameAncestors) {
    checks.push({ name: 'X-Frame-Options', key: 'x-frame-options', weight: 10, value: xfo ?? 'CSP frame-ancestors', status: 'pass', detail: xfo ? `Valor: ${xfo}` : 'Protegido por frame-ancestors en la CSP.', score: 10 });
  } else {
    checks.push({ name: 'X-Frame-Options', key: 'x-frame-options', weight: 10, value: null, status: 'fail', detail: 'No está. Evita que otro sitio muestre el tuyo dentro de un marco para engañar clics.', score: 0 });
  }

  // 5. Referrer-Policy (10 pts)
  const rp = headers.get('referrer-policy');
  if (rp) {
    checks.push({ name: 'Referrer-Policy', key: 'referrer-policy', weight: 10, value: rp, status: 'pass', detail: `Valor: ${rp}`, score: 10 });
  } else {
    checks.push({ name: 'Referrer-Policy', key: 'referrer-policy', weight: 10, value: null, status: 'fail', detail: 'No está. Controla qué datos de tu sitio se pasan al hacer clic hacia otro.', score: 0 });
  }

  // 6. Permissions-Policy (10 pts)
  const pp = headers.get('permissions-policy');
  if (pp) {
    checks.push({ name: 'Permissions-Policy', key: 'permissions-policy', weight: 10, value: pp, status: 'pass', detail: 'Permissions-Policy configurado.', score: 10 });
  } else {
    checks.push({ name: 'Permissions-Policy', key: 'permissions-policy', weight: 10, value: null, status: 'fail', detail: 'No está. Limita el acceso a cámara, micrófono, ubicación, etc.', score: 0 });
  }

  // 7. X-XSS-Protection (5 pts)
  // X-XSS-Protection is obsolete; "1; mode=block" can even introduce issues. Informative only, 5 pts unless enabled.
  const xxss = headers.get('x-xss-protection');
  const xxssOk = !xxss || xxss.trim().startsWith('0');
  checks.push({ name: 'X-XSS-Protection', key: 'x-xss-protection', weight: 5, value: xxss, status: xxssOk ? 'pass' : 'warning', detail: xxssOk ? 'Header obsoleto: está bien no tenerlo o tenerlo en 0.' : 'Header obsoleto. Recomendado: sacarlo o ponerlo en 0 y usar CSP.', score: xxssOk ? 5 : 2 });

  const totalScore = checks.reduce((sum, c) => sum + c.score, 0);
  const grade = computeGrade(totalScore);

  return { url: finalUrl, score: { total: totalScore, grade }, headers: checks };
}
