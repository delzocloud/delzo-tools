/**
 * Minimal public-suffix handling to find the organizational domain (RFC 7489 §3.2).
 * Not a full PSL: covers generic TLDs plus the second-level suffixes that matter
 * most for LATAM / Spain clients. Unknown multi-label suffixes fall back to the
 * last two labels.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  // Argentina
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'gov.ar', 'edu.ar', 'int.ar', 'mil.ar', 'tur.ar', 'coop.ar', 'mutual.ar', 'musica.ar', 'senasa.ar', 'bet.ar', 'seg.ar', 'juegos.ar',
  // Region
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'com.mx', 'org.mx', 'gob.mx', 'edu.mx', 'net.mx',
  'com.uy', 'org.uy', 'gub.uy', 'edu.uy', 'com.py', 'org.py', 'gov.py', 'edu.py', 'com.bo', 'gob.bo',
  'com.pe', 'org.pe', 'gob.pe', 'edu.pe', 'net.pe', 'com.co', 'org.co', 'gov.co', 'edu.co', 'net.co',
  'com.ec', 'gob.ec', 'org.ec', 'com.ve', 'gob.ve', 'org.ve', 'gob.cl', 'com.es', 'org.es', 'gob.es', 'edu.es', 'nom.es',
  // Common elsewhere
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.za', 'com.cn', 'com.tr',
]);

export function organizationalDomain(domain: string): string {
  const labels = domain.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  const n = MULTI_LABEL_SUFFIXES.has(lastTwo) ? 3 : 2;
  return labels.slice(-n).join('.');
}
