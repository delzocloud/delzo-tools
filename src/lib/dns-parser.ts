import type { AuthStatus, SpfResult, DmarcResult, DkimResult, DkimKey, SpfQualifier } from './types';
import { queryTxt } from './dns-client';
import { organizationalDomain } from './psl';
import { computeGrade, type GradeResult } from './grading';

export type TxtResolver = (name: string) => Promise<{ nxdomain: boolean; records: string[] }>;

const errMsg = (e: unknown) => (e instanceof Error && e.name === 'DnsError' ? e.message : 'No pudimos consultar el DNS en este momento.');

/* ------------------------------------------------------------------ */
/* Scoring                                                            */
/* ------------------------------------------------------------------ */

export interface EmailScore {
  total: number;
  spfScore: number;
  dmarcScore: number;
  dkimScore: number;
  grade: GradeResult;
}

export function computeEmailScore(spf: SpfResult, dmarc: DmarcResult, dkim: DkimResult): EmailScore {
  // SPF: 30 pts max
  let spfScore = 0;
  if (spf.record && spf.status !== 'fail' && spf.status !== 'error') {
    spfScore = { '-': 30, '~': 25, '?': 10, '+': 0 }[spf.allQualifier ?? '?'] ?? 10;
  }

  // DMARC: 40 pts max. reject > quarantine > none.
  let dmarcScore = 0;
  if (dmarc.record && dmarc.status !== 'error') {
    const p = dmarc.effectivePolicy;
    dmarcScore = p === 'reject' ? 36 : p === 'quarantine' ? 30 : p === 'none' ? 10 : 0;
    if (dmarcScore > 0 && dmarc.rua) dmarcScore += 4;
    if (dmarcScore > 0 && p !== 'none' && dmarc.pct < 100) dmarcScore -= 6;
  }

  // DKIM: 30 pts, nothing without a valid (non revoked) key.
  const dkimScore = dkim.keys.some((k) => !k.revoked) ? 30 : 0;

  const total = spfScore + dmarcScore + dkimScore;
  return { total, spfScore, dmarcScore, dkimScore, grade: computeGrade(total) };
}

/* ------------------------------------------------------------------ */
/* SPF                                                                */
/* ------------------------------------------------------------------ */

export const SPF_MAX_LOOKUPS = 10;
const SPF_RE = /^v=spf1(\s|$)/i;

export interface SpfTerm {
  qualifier: SpfQualifier;
  mechanism: string; // all | include | a | mx | ptr | ip4 | ip6 | exists
  value: string | null;
}

export interface ParsedSpf {
  terms: SpfTerm[];
  redirect: string | null;
  all: SpfQualifier | null;
}

/** Exact, token based parse. Case insensitive. */
export function parseSpf(record: string): ParsedSpf {
  const tokens = record.trim().split(/\s+/).slice(1);
  const terms: SpfTerm[] = [];
  let redirect: string | null = null;
  for (const tok of tokens) {
    const mod = tok.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
    if (mod) {
      if (mod[1].toLowerCase() === 'redirect') redirect = mod[2];
      continue;
    }
    const m = tok.match(/^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?:[:/](.*))?$/i);
    if (!m) continue;
    terms.push({ qualifier: (m[1] || '+') as SpfQualifier, mechanism: m[2].toLowerCase(), value: m[3] ?? null });
  }
  const allTerm = terms.find((t) => t.mechanism === 'all');
  return { terms, redirect, all: allTerm ? allTerm.qualifier : null };
}

const LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

export interface SpfEvaluation {
  lookups: number;
  /** "all" qualifier after following redirect= */
  effectiveAll: SpfQualifier | null;
  problems: string[];
}

/**
 * Recursively counts DNS-querying terms (RFC 7208 §4.6.4) following include: and
 * redirect=. Loop safe and bounded: stops fetching once the limit is passed.
 */
export async function evaluateSpf(record: string, resolve: TxtResolver, domain: string): Promise<SpfEvaluation> {
  const state = { lookups: 0, problems: [] as string[], visited: new Set<string>([domain.toLowerCase()]) };

  async function fetchSpf(target: string): Promise<string | null> {
    try {
      const { records } = await resolve(target);
      const spfs = records.filter((r) => SPF_RE.test(r));
      if (spfs.length === 0) {
        state.problems.push(`${target} no tiene registro SPF (lo referencia tu SPF).`);
        return null;
      }
      if (spfs.length > 1) state.problems.push(`${target} tiene más de un registro SPF.`);
      return spfs[0];
    } catch {
      state.problems.push(`No pudimos consultar el SPF de ${target}.`);
      return null;
    }
  }

  async function walk(rec: string, depth: number): Promise<SpfQualifier | null> {
    const parsed = parseSpf(rec);
    for (const t of parsed.terms) {
      if (!LOOKUP_MECHS.has(t.mechanism)) continue;
      state.lookups++;
      if (t.mechanism === 'include' && t.value) {
        const target = t.value.toLowerCase().replace(/\.$/, '');
        if (state.visited.has(target)) {
          state.problems.push(`Hay un bucle: ${target} se incluye a sí mismo.`);
          continue;
        }
        if (state.lookups > SPF_MAX_LOOKUPS || depth >= 10) continue;
        state.visited.add(target);
        const sub = await fetchSpf(target);
        if (sub) await walk(sub, depth + 1);
      }
    }
    if (parsed.all) return parsed.all;
    if (parsed.redirect) {
      state.lookups++;
      const target = parsed.redirect.toLowerCase().replace(/\.$/, '');
      if (state.visited.has(target)) {
        state.problems.push(`Hay un bucle en redirect=${target}.`);
        return null;
      }
      if (state.lookups > SPF_MAX_LOOKUPS || depth >= 10) return null;
      state.visited.add(target);
      const sub = await fetchSpf(target);
      return sub ? walk(sub, depth + 1) : null;
    }
    return null;
  }

  const effectiveAll = await walk(record, 0);
  return { lookups: state.lookups, effectiveAll, problems: state.problems };
}

export async function analyzeSpf(domain: string, resolve: TxtResolver = queryTxt): Promise<SpfResult> {
  const base = { records: [] as string[], allQualifier: null, lookups: 0 };
  let records: string[];
  try {
    records = (await resolve(domain)).records.filter((r) => SPF_RE.test(r));
  } catch (e) {
    return { ...base, status: 'error', record: null, details: `No pudimos revisar SPF: ${errMsg(e)}`, recommendation: 'Probá de nuevo en unos minutos.' };
  }

  if (records.length === 0) {
    return {
      ...base,
      status: 'fail',
      record: null,
      details: 'No encontramos registro SPF. Sin SPF, cualquiera puede mandar mails que parecen tuyos y los tuyos pueden ir a spam.',
      recommendation: `Agregá un registro TXT en ${domain} con los servidores que mandan tus mails. Ejemplo con Google: v=spf1 include:_spf.google.com ~all`,
    };
  }

  if (records.length > 1) {
    return {
      ...base,
      records,
      status: 'fail',
      record: records[0],
      details: `Encontramos ${records.length} registros SPF. Solo puede haber uno: con más de uno, los proveedores lo dan por inválido.`,
      recommendation: 'Uní todos en un solo registro, por ejemplo: v=spf1 include:proveedor1 include:proveedor2 ~all, y borrá los demás.',
    };
  }

  const record = records[0];
  const ev = await evaluateSpf(record, resolve, domain);
  const q = ev.effectiveAll;
  let status: AuthStatus = 'pass';
  let details: string;
  let recommendation = 'Tu SPF está bien configurado.';

  if (q === '+') {
    status = 'fail';
    details = 'Tu SPF termina en "+all": autoriza a cualquier servidor del mundo a mandar mails con tu dominio.';
    recommendation = 'Cambiá "+all" por "~all" o "-all".';
  } else if (q === '?' || q === null) {
    status = 'warning';
    details = q === null
      ? 'Tu SPF no termina en "all", así que no le dice a nadie qué hacer con mails falsos.'
      : 'Tu SPF termina en "?all" (neutral): no protege contra mails falsos.';
    recommendation = 'Terminá el registro con "~all" (recomendado para empezar) o "-all".';
  } else if (q === '~') {
    details = 'SPF configurado. Los mails de servidores no autorizados se marcan como sospechosos (~all).';
  } else {
    details = 'SPF configurado en modo estricto (-all): se rechazan los mails de servidores no autorizados.';
  }

  if (ev.lookups > SPF_MAX_LOOKUPS) {
    status = 'fail';
    details += ` Pero tu SPF necesita ${ev.lookups} consultas DNS y el máximo es ${SPF_MAX_LOOKUPS}: los proveedores lo dan por inválido.`;
    recommendation = 'Sacá los include que ya no uses o reemplazalos por ip4:/ip6: para bajar de 10 consultas.';
  } else if (ev.problems.length > 0) {
    if (status === 'pass') status = 'warning';
    details += ` Atención: ${ev.problems.join(' ')}`;
  }

  return { status, record, records, allQualifier: q, lookups: ev.lookups, details, recommendation };
}

/* ------------------------------------------------------------------ */
/* DMARC                                                              */
/* ------------------------------------------------------------------ */

const DMARC_RE = /^v\s*=\s*DMARC1\s*(;|$)/i;

export function parseDmarcTags(record: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(i + 1).trim();
  }
  return tags;
}

const VALID_POLICIES = new Set(['none', 'quarantine', 'reject']);

export async function analyzeDmarc(domain: string, resolve: TxtResolver = queryTxt): Promise<DmarcResult> {
  const empty = { record: null, policy: null, subdomainPolicy: null, effectivePolicy: null, pct: 100, rua: false, inheritedFrom: null };
  const org = organizationalDomain(domain);

  let records: string[];
  let inheritedFrom: string | null = null;
  try {
    records = (await resolve(`_dmarc.${domain}`)).records.filter((r) => DMARC_RE.test(r));
    if (records.length === 0 && org !== domain) {
      records = (await resolve(`_dmarc.${org}`)).records.filter((r) => DMARC_RE.test(r));
      if (records.length > 0) inheritedFrom = org;
    }
  } catch (e) {
    return { ...empty, status: 'error', details: `No pudimos revisar DMARC: ${errMsg(e)}`, recommendation: 'Probá de nuevo en unos minutos.' };
  }

  if (records.length === 0) {
    return {
      ...empty,
      status: 'fail',
      details: 'No encontramos DMARC. Sin DMARC, Gmail y Outlook no saben qué hacer con mails falsos que usan tu dominio.',
      recommendation: `Agregá un registro TXT en _dmarc.${org} con: v=DMARC1; p=none; rua=mailto:dmarc@${org} (y después de unas semanas pasalo a p=quarantine).`,
    };
  }

  if (records.length > 1) {
    return {
      ...empty,
      record: records[0],
      inheritedFrom,
      status: 'fail',
      details: `Encontramos ${records.length} registros DMARC. Solo puede haber uno: con más de uno, se ignoran todos.`,
      recommendation: 'Dejá un solo registro DMARC y borrá los demás.',
    };
  }

  const record = records[0];
  const tags = parseDmarcTags(record);
  const policy = VALID_POLICIES.has(tags.p?.toLowerCase()) ? tags.p.toLowerCase() : null;
  const subdomainPolicy = VALID_POLICIES.has(tags.sp?.toLowerCase()) ? tags.sp.toLowerCase() : null;
  const pctRaw = parseInt(tags.pct ?? '100', 10);
  const pct = Number.isFinite(pctRaw) ? Math.min(100, Math.max(0, pctRaw)) : 100;
  const rua = /mailto:/i.test(tags.rua ?? '');
  const effectivePolicy = inheritedFrom ? subdomainPolicy ?? policy : policy;

  let status: AuthStatus = 'pass';
  let details: string;
  let recommendation = 'Tu DMARC está bien configurado.';
  const from = inheritedFrom ? ` (lo hereda de ${inheritedFrom})` : '';

  if (!policy) {
    status = 'fail';
    details = `Tu DMARC${from} no tiene una política válida (p=).`;
    recommendation = 'Agregá p=quarantine o p=reject al registro.';
  } else if (effectivePolicy === 'none') {
    status = 'warning';
    details = `DMARC en modo "none"${from}: solo observa, no frena mails falsos.`;
    recommendation = 'Cuando confirmes que tus mails legítimos pasan, cambiá a p=quarantine y después a p=reject.';
  } else if (effectivePolicy === 'quarantine') {
    details = `DMARC en "quarantine"${from}: los mails falsos van a spam.`;
    recommendation = 'Buen nivel. El paso final es p=reject para que los mails falsos ni lleguen.';
  } else {
    details = `DMARC en "reject"${from}: los mails falsos se rechazan. Es el nivel más alto.`;
  }

  if (policy && pct < 100 && effectivePolicy !== 'none') {
    status = 'warning';
    details += ` Solo se aplica al ${pct}% de los mails (pct=${pct}).`;
    recommendation += ' Subí pct a 100 (o sacalo) para que proteja todos los mails.';
  }
  if (!rua) recommendation += ' Sumá rua=mailto:... para recibir reportes y ver quién manda mails con tu dominio.';

  return { status, record, policy, subdomainPolicy, effectivePolicy, pct, rua, inheritedFrom, details, recommendation };
}

/* ------------------------------------------------------------------ */
/* DKIM                                                               */
/* ------------------------------------------------------------------ */

export const DKIM_SELECTORS = [
  'google', 'default', 'selector1', 'selector2', 'k1', 'k2', 'k3', 's1', 's2', 'dkim', 'mail', 'smtp',
  'brevo1', 'brevo2', 'mandrill', 'mailjet', 'resend', 'amazonses', 'mxvault', 'zoho', 'zmail',
  'protonmail', 'protonmail2', 'protonmail3', 'fm1', 'fm2', 'hs1', 'hs2', 'titan1', 'hostingermail1', 'cm', 'sig1',
];

export function parseDkim(record: string): { valid: boolean; revoked: boolean } {
  const tags = parseDmarcTags(record); // same tag=value; syntax
  const looksDkim = /^v\s*=\s*DKIM1/i.test(record) || 'p' in tags;
  if (!looksDkim || !('p' in tags)) return { valid: false, revoked: false };
  return { valid: true, revoked: tags.p.replace(/\s+/g, '') === '' };
}

export async function analyzeDkim(domain: string, resolve: TxtResolver = queryTxt, extraSelector?: string): Promise<DkimResult> {
  const selectors = [...new Set([...(extraSelector ? [extraSelector] : []), ...DKIM_SELECTORS])];
  const results = await Promise.allSettled(
    selectors.map(async (selector) => {
      const { records } = await resolve(`${selector}._domainkey.${domain}`);
      for (const r of records) {
        const p = parseDkim(r);
        if (p.valid) return { selector, record: r, revoked: p.revoked } as DkimKey;
      }
      return null;
    }),
  );

  const keys = results.flatMap((r) => (r.status === 'fulfilled' && r.value ? [r.value] : []));
  const allFailed = results.every((r) => r.status === 'rejected');
  const active = keys.filter((k) => !k.revoked);
  const first = active[0] ?? keys[0];

  if (allFailed) {
    return { status: 'error', record: null, selector: '', keys, checkedSelectors: selectors, details: 'No pudimos revisar DKIM porque el DNS no respondió.', recommendation: 'Probá de nuevo en unos minutos.' };
  }
  if (active.length > 0) {
    const names = active.map((k) => `"${k.selector}"`).join(', ');
    return { status: 'pass', record: first.record, selector: first.selector, keys, checkedSelectors: selectors, details: `DKIM encontrado (${names}). Tus mails van firmados.`, recommendation: 'Tu DKIM está bien configurado.' };
  }
  if (keys.length > 0) {
    return { status: 'warning', record: first.record, selector: first.selector, keys, checkedSelectors: selectors, details: `Encontramos una clave DKIM "${first.selector}" pero está revocada (p= vacío), así que no firma nada.`, recommendation: 'Generá una clave nueva desde tu proveedor de email y publicala en el DNS.' };
  }
  return {
    status: 'warning',
    record: null,
    selector: '',
    keys,
    checkedSelectors: selectors,
    details: 'No encontramos DKIM con los nombres más comunes. Puede que uses otro nombre (selector) o que no esté activado.',
    recommendation: 'Revisá en tu proveedor de email (Google, Microsoft, Brevo, etc.) cómo activar DKIM, o ingresá tu selector si lo conocés.',
  };
}
