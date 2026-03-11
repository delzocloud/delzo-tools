export const prerender = false;

import type { APIRoute } from 'astro';

interface SubdomainResult {
  name: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
}

export const GET: APIRoute = async ({ url }) => {
  const domain = url.searchParams.get('domain')?.trim().toLowerCase();

  if (!domain) {
    return json({ error: 'Ingresá un dominio.' }, 400);
  }

  if (!isValidDomain(domain)) {
    return json({ error: 'Dominio inválido.' }, 400);
  }

  try {
    const subdomains = await findSubdomains(domain);
    return json({ 
      domain, 
      subdomains, 
      total: subdomains.length 
    });
  } catch (err: any) {
    return json({ error: err.message || 'Error al buscar subdominios.' }, 500);
  }
};

async function findSubdomains(domain: string): Promise<SubdomainResult[]> {
  // Use crt.sh - public Certificate Transparency log aggregator
  const url = `https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`;
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (compatible; DelzoTools/1.0)',
      },
    });

    clearTimeout(timeout);

    if (!response.ok) {
      throw new Error(`crt.sh respondió con ${response.status}`);
    }

    const data = await response.json();
    
    if (!Array.isArray(data)) {
      return [];
    }

    // Process and deduplicate subdomains
    const seen = new Set<string>();
    const results: SubdomainResult[] = [];

    for (const entry of data) {
      const nameValue = entry.name_value?.toLowerCase().trim();
      if (!nameValue) continue;

      // crt.sh returns entries with wildcards like *.example.com
      // and also individual subdomains
      const subdomains = nameValue.split('\n').map((s: string) => s.trim());
      
      for (const subdomain of subdomains) {
        // Clean up wildcard prefix
        const cleanSubdomain = subdomain.replace(/^\*\./, '');
        
        // Skip the root domain itself
        if (cleanSubdomain === domain) continue;
        
        // Skip duplicates
        if (seen.has(cleanSubdomain)) continue;
        
        // Validate it actually belongs to the domain
        if (!cleanSubdomain.endsWith('.' + domain) && cleanSubdomain !== domain) continue;
        
        seen.add(cleanSubdomain);
        
        results.push({
          name: cleanSubdomain,
          issuer: entry.issuer_name || 'Unknown',
          notBefore: entry.not_before || '',
          notAfter: entry.not_after || '',
        });
      }
    }

    // Sort alphabetically
    results.sort((a, b) => a.name.localeCompare(b.name));

    return results;

  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

function isValidDomain(domain: string): boolean {
  // Basic domain validation
  const pattern = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/i;
  return pattern.test(domain) && domain.includes('.') && domain.length <= 253;
}

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
