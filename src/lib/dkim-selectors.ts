/**
 * DKIM selectors by provider. Sources: provider docs and the dkim.fyi selector
 * dataset (https://dkim.fyi/selectors, consulted 2026-10-16).
 * Some providers generate unguessable selectors (Amazon SES Easy DKIM, Postmark
 * dated "...pm", Unosend, HubSpot, IONOS per-account, Constant Contact): we cannot
 * find those by probing, so a miss never means "no DKIM".
 *
 * Workers limit subrequests per request, so the probe list is capped (MAX_PROBES).
 */
export interface SelectorProvider {
  provider: string;
  selectors: string[];
  /** Matches an include:/redirect= domain in SPF, to probe this provider first. */
  spf?: RegExp;
  /** Matches the CNAME target of a DKIM record. */
  cname?: RegExp;
}

export const PROVIDER_SELECTORS: SelectorProvider[] = [
  { provider: 'Google Workspace', selectors: ['google'], spf: /(^|\.)_spf\.google\.com$/, cname: /google/ },
  { provider: 'Microsoft 365', selectors: ['selector1', 'selector2'], spf: /(^|\.)protection\.outlook\.com$/, cname: /(onmicrosoft\.com|dkim\.mail\.microsoft)$/ },
  { provider: 'Brevo (Sendinblue)', selectors: ['brevo1', 'brevo2', 'mail', 'sendinblue', 'brevo'], spf: /(brevo\.com|sendinblue\.com)$/, cname: /(brevo\.com|sendinblue\.com)$/ },
  { provider: 'Mailgun', selectors: ['pdk1', 'pdk2', 'k1', 'mx', 'krs', 'smtp', 'mailo', 'pic', 'mg'], spf: /mailgun\.org$/, cname: /(mailgun\.(com|org)|mgsend\.org)$/ },
  { provider: 'SendGrid', selectors: ['s1', 's2', 'smtpapi', 'm1'], spf: /sendgrid\.net$/, cname: /sendgrid\.net$/ },
  { provider: 'Mailchimp Transactional (Mandrill)', selectors: ['mte1', 'mte2', 'mandrill'], spf: /mandrillapp\.com$/, cname: /mandrillapp\.com$/ },
  { provider: 'Mailchimp', selectors: ['k1', 'k2', 'k3'], spf: /(mcsv\.net|mailchimp\.com)$/, cname: /(mcsv\.net|mailchimp\.com)$/ },
  { provider: 'Resend', selectors: ['resend'], spf: /resend\.(com|dev)$/, cname: /resend/ },
  { provider: 'Amazon SES', selectors: ['amazonses', 'ses'], spf: /amazonses\.com$/, cname: /amazonses\.com$/ },
  { provider: 'Postmark', selectors: ['pm', 'pm2'], spf: /(mtasv\.net|postmarkapp\.com)$/, cname: /(mtasv\.net|postmarkapp\.com)$/ },
  { provider: 'Zoho Mail', selectors: ['zoho', 'zmail'], spf: /zoho\.(com|eu|in)$/, cname: /zoho/ },
  { provider: 'Mailjet', selectors: ['mailjet'], spf: /mailjet\.com$/, cname: /mailjet\.com$/ },
  { provider: 'SparkPost', selectors: ['scph0316', 'scph0325', 'scph1224'], spf: /sparkpostmail\.com$/, cname: /sparkpostmail\.com$/ },
  { provider: 'Proton Mail', selectors: ['protonmail', 'protonmail2', 'protonmail3'], spf: /protonmail\.ch$/, cname: /protonmail\.ch$/ },
  { provider: 'Fastmail', selectors: ['fm1', 'fm2', 'fm3'], spf: /messagingengine\.com$/, cname: /fmhosted\.com$/ },
  { provider: 'Hostinger', selectors: ['hostingermail-a', 'hostingermail-b', 'hostingermail-c'], spf: /hostinger\.com$/, cname: /hostinger\.com$/ },
  { provider: 'Titan Mail', selectors: ['titan1'], spf: /titan\.email$/, cname: /titan\.email$/ },
  { provider: 'iCloud+', selectors: ['sig1'], spf: /icloud\.com$/, cname: /icloud\.com$/ },
  { provider: 'Cloudflare Email', selectors: ['cf2024-1', 'cf-bounce'], spf: /mx\.cloudflare\.net$/, cname: /cloudflare/ },
  { provider: 'Zendesk', selectors: ['zendesk1', 'zendesk2'], spf: /zendesk\.com$/, cname: /zendesk\.com$/ },
  { provider: 'Klaviyo', selectors: ['km1', 'km2', 'kl1', 'kl2'], spf: /klaviyo/, cname: /klaviyo/ },
  { provider: 'HubSpot', selectors: ['hs1', 'hs2'], spf: /hubspotemail\.net$/, cname: /hubspotemail\.net$/ },
  { provider: 'Unosend', selectors: [], spf: /unosend\.co$/, cname: /unosend/ },
];

/** Generic names tried when nothing provider-specific matched. */
export const GENERIC_SELECTORS = ['default', 'dkim', 'mail', 'k1', 's1', 's2', 'key1', 'key2', 'smtp', 'email', 'selector'];

export const MAX_PROBES = 30;

const BY_SELECTOR = new Map<string, string>();
for (const p of PROVIDER_SELECTORS) for (const s of p.selectors) if (!BY_SELECTOR.has(s)) BY_SELECTOR.set(s, p.provider);

export function providerFromCname(cnames: string[] | undefined): string | null {
  for (const c of cnames ?? []) for (const p of PROVIDER_SELECTORS) if (p.cname?.test(c)) return p.provider;
  return null;
}

/** Ambiguous generic names (k1, s1, mail) are attributed only via CNAME. */
const AMBIGUOUS = new Set(['k1', 's1', 's2', 'mail', 'smtp', 'mx', 'default', 'dkim']);
export function providerFromSelector(sel: string): string | null {
  if (AMBIGUOUS.has(sel)) return null;
  return BY_SELECTOR.get(sel) ?? null;
}

/** Providers hinted by SPF include:/redirect= targets. */
export function providersFromSpf(spf: string | null | undefined): SelectorProvider[] {
  if (!spf) return [];
  const targets = [...spf.matchAll(/(?:include:|redirect=)([^\s]+)/gi)].map((m) => m[1].toLowerCase().replace(/\.$/, ''));
  return PROVIDER_SELECTORS.filter((p) => p.spf && targets.some((t) => p.spf!.test(t)));
}

/**
 * Ordered probe list after "google": SPF-hinted providers, then the main providers,
 * then generic names. Deduped and capped.
 */
export function probeOrder(spf: string | null | undefined, extra?: string): string[] {
  const out: string[] = [];
  const add = (s: string) => { if (!out.includes(s)) out.push(s); };
  if (extra) add(extra);
  for (const p of providersFromSpf(spf)) p.selectors.forEach(add);
  for (const p of PROVIDER_SELECTORS) p.selectors.slice(0, 2).forEach(add);
  GENERIC_SELECTORS.forEach(add);
  return out.filter((s) => s !== 'google').slice(0, MAX_PROBES - 2); // google + wildcard probe use 2
}
