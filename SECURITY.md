# Security and dependency policy

## Reporting a problem

Write to hola@delzo.cloud. Please don't open a public issue for a vulnerability.

## How versions are updated

We want to stay current without being the first ones to install a release. Most
malicious npm versions get detected and pulled within a few days, and most
regressions show up in the first patch releases. So:

| What | Rule | Where it's enforced |
|---|---|---|
| Any new version | Must have been published at least **14 days** ago | `.npmrc` (`min-release-age=14`) and Dependabot `cooldown` |
| Minor and patch | One grouped Dependabot PR per week | `.github/dependabot.yml` |
| Major | Separate PR, only after **60 days**. Read the upgrade guide, test the preview, then merge | `.github/dependabot.yml` |
| Security fix | Skips the cooldown. Dependabot security updates open a PR as soon as there is an advisory | Repo setting "Dependabot security updates" |
| Exact pins | `package.json` uses exact versions, no `^` ranges | `.npmrc` (`save-exact=true`) |
| Install scripts | Never run (`postinstall` and friends) | `.npmrc` (`ignore-scripts=true`) |
| GitHub Actions | Pinned to a full commit SHA with the version as a comment, also 14 days of cooldown | Workflows + Dependabot |

**Don't fall more than one major behind.** The Astro team only backports security
fixes to the previous major, and in practice even that stops soon after a new major
ships. Astro 5 got its last fix in May 2026, and fixes published after July only
landed in 7.x. An upgrade postponed too long ends up being an emergency upgrade.

### Urgent security fix newer than 14 days

```bash
npm install <package>@<version> --min-release-age=0
```

Leave a note in the PR explaining why it skipped the cooldown.

### Transitive fix that the parent package hasn't picked up yet

Use `overrides` in `package.json`, scoped to the parent package, and remove it as
soon as the parent ships the fix. Current one:

- `miniflare > undici@7.30.1` (GHSA-2m5v-pch6-74hx and others). Only affects local
  dev/build tooling, not the deployed Worker. Remove it when `wrangler` and
  `@cloudflare/vite-plugin` depend on `undici >= 7.30.1`.

## What CI checks

Every PR and every push to `main` runs these, and **nothing deploys (preview or
production) unless they pass**:

1. `npm audit signatures`: every package comes from the npm registry with a valid signature.
2. `npm audit --audit-level=high`: blocks on high/critical advisories.
3. `npm test` and `npm run build`.
4. [zizmor](https://docs.zizmor.sh/): static analysis of the workflows (template
   injection, excessive permissions, unpinned actions).
5. On PRs, `dependency-review-action`: blocks new dependencies with high
   advisories or GPL/AGPL licenses.

Separately, `security.yml` runs CodeQL (`security-extended`) on the code and the
workflows, and repeats the audit every Monday against `main`, so a new advisory
shows up even when nobody pushes.

## Runtime protections already in place

- SSRF guard (`src/lib/url-guard.ts`) on every tool that fetches a user-supplied
  URL: http/https only, ports 80/443, private ranges blocked before and after DNS,
  every redirect re-validated.
- Security headers (CSP, `X-Frame-Options`, `nosniff`, `Referrer-Policy`,
  `Permissions-Policy`, COOP) in `public/_headers` for static pages and in
  `src/middleware.ts` for SSR/API. **Keep both in sync.**
- CORS limited to `delzo.cloud`, `www.delzo.cloud` and `tools.delzo.cloud`.
- Third-party scripts loaded with SRI (`integrity=`), for example Leaflet.
