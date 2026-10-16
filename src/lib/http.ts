export function json(data: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders },
  });
}

export const USER_AGENT = 'DelzoTools/1.0 (+https://tools.delzo.cloud)';

const LABEL_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

/**
 * Normalizes user input into an ASCII hostname (IDN to punycode) or null if invalid.
 * Accepts "Ejemplo.com", "https://ejemplo.com/x", "ñandú.com.ar".
 */
export function normalizeDomain(input: string | null | undefined): string | null {
  if (!input) return null;
  let s = input.trim().toLowerCase();
  if (!s || s.length > 253) return null;
  s = s.replace(/^[a-z]+:\/\//, '').split(/[/?#]/)[0].replace(/\.$/, '');
  if (s.includes('@') || s.includes(':')) return null;
  let host: string;
  try {
    host = new URL(`http://${s}`).hostname;
  } catch {
    return null;
  }
  const labels = host.split('.');
  if (labels.length < 2) return null;
  if (!labels.every((l) => LABEL_RE.test(l))) return null;
  const tld = labels[labels.length - 1];
  if (!/^([a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(tld)) return null;
  return host;
}

/** Turns internal errors into a Spanish message safe to show. */
export function publicError(err: unknown, fallback: string): string {
  if (err && typeof err === 'object' && 'name' in err) {
    const e = err as { name: string; message?: string };
    if (e.name === 'DnsError' || e.name === 'GuardError') return e.message || fallback;
    if (e.name === 'AbortError' || e.name === 'TimeoutError') return 'El sitio tardó demasiado en responder.';
  }
  console.error(err);
  return fallback;
}
