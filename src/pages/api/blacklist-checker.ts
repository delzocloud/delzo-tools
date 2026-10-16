export const prerender = false;

import type { APIRoute } from 'astro';
import { json, normalizeDomain, publicError } from '../../lib/http';
import { checkBlacklists } from '../../lib/blacklist-checker';

const IP_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

export const GET: APIRoute = async ({ url }) => {
  const targetsParam = url.searchParams.get('targets')?.trim().toLowerCase();
  const target = url.searchParams.get('target')?.trim().toLowerCase();

  // Support both 'targets' (comma-separated) and 'target' (single) for backwards compatibility
  let targets: string[] = [];
  if (targetsParam) {
    targets = targetsParam.split(',').map(t => t.trim()).filter(t => t.length > 0);
  } else if (target) {
    targets = [target];
  }

  if (targets.length > 5) {
    return json({ error: 'Podés revisar hasta 5 IPs o dominios por vez.' }, 400);
  }

  if (targets.length === 0) {
    return json({ error: 'Ingresá al menos una IP o dominio.' }, 400);
  }

  // Validate all targets
  const invalidTargets = targets.filter(t => !normalizeDomain(t) && !IP_RE.test(t));
  if (invalidTargets.length > 0) {
    return json({ error: `IPs o dominios inválidos: ${invalidTargets.join(', ')}` }, 400);
  }

  try {
    // Check all targets in parallel
    const results = await Promise.all(
      targets.map(async (t) => {
        try {
          return await checkBlacklists(t);
        } catch (err) {
          return {
            ip: t,
            error: publicError(err, 'Error al verificar blacklists.'),
            total: 0,
            listed: 0,
            clean: 0,
            results: [],
          };
        }
      })
    );

    // Return single result for backwards compatibility, array for multiple
    return json(targets.length === 1 ? results[0] : results);
  } catch (err) {
    return json({ error: publicError(err, 'Error al verificar blacklists.') }, 500);
  }
};

