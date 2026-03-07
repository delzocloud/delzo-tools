export const prerender = false;

import type { APIRoute } from 'astro';
import { checkBlacklists } from '../../lib/blacklist-checker';

const DOMAIN_RE = /^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

export const GET: APIRoute = async ({ url }) => {
  const target = url.searchParams.get('target')?.trim().toLowerCase();

  if (!target) {
    return json({ error: 'El parámetro "target" es requerido.' }, 400);
  }

  if (!DOMAIN_RE.test(target) && !IP_RE.test(target)) {
    return json({ error: 'Ingresá una IP o dominio válido.' }, 400);
  }

  try {
    const report = await checkBlacklists(target);
    return json(report);
  } catch (err: any) {
    return json({ error: err.message || 'Error al verificar blacklists.' }, 500);
  }
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
