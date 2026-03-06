# CLAUDE.md — delzo-tools

## What This Is

Free networking tools site for **delzo.cloud** ("engineering as marketing"). Attracts IT professionals at Latin American SMEs, positions Delzo as technical authority. Lives at `tools.delzo.cloud`.

**Parent brand context:** See `delzocloud/delzo-marketing` repo → `.claude/product-marketing-context.md` for full brand positioning, audience, and messaging guidelines.

## Stack

- **Astro 5** (static output + server endpoints) — `astro.config.mjs`
- **Cloudflare Workers** via `@astrojs/cloudflare` adapter — `wrangler.jsonc`
- **No JS frameworks** — vanilla JS in `<script>` tags, Astro components for HTML

## Commands

```bash
npm run dev       # Local dev server (http://localhost:4321)
npm run build     # Production build → dist/
npm run preview   # Preview production build locally
npm run deploy    # astro build && wrangler deploy
```

After modifying `astro.config.mjs` or adding integrations, restart dev server.

## Architecture

```
src/
├── pages/           # File-based routing
│   ├── index.astro              # Homepage (prerendered)
│   ├── dns-lookup.astro         # DNS Lookup tool (prerendered)
│   ├── email-auth.astro         # SPF/DMARC/DKIM analyzer (prerendered)
│   ├── cidr-calculator.astro    # CIDR calculator (prerendered, 100% client-side)
│   ├── ip-geolocation.astro     # IP geolocation + Leaflet map (prerendered)
│   └── api/                     # Server endpoints (Cloudflare Workers)
│       ├── dns.ts               # GET /api/dns?domain=...&type=A
│       ├── email-auth.ts        # GET /api/email-auth?domain=...
│       └── geoip.ts             # GET /api/geoip?ip=... (optional, auto-detect)
├── components/      # Astro components
│   ├── Header.astro             # Nav + wordmark "delzo.cloud / tools"
│   ├── Footer.astro             # Simple branding footer
│   ├── ToolLayout.astro         # Wrapper: heading + form slot + results slot
│   └── ToolCard.astro           # Card for homepage grid
├── layouts/
│   └── BaseLayout.astro         # HTML shell, fonts, meta, CSS import
├── lib/             # Pure TypeScript (server-side)
│   ├── dns-client.ts            # Cloudflare DoH wrapper
│   ├── dns-parser.ts            # SPF/DMARC/DKIM parsing + recommendations
│   └── types.ts                 # Shared TypeScript interfaces
└── styles/
    └── global.css               # CSS variables, utility classes, responsive
```

### Key patterns

- **Pages are prerendered** (static HTML) by default. API endpoints opt out with `export const prerender = false;`
- **CSS imported in frontmatter** (`import '../styles/global.css'` in BaseLayout) — NOT in `<style>` blocks. This is the correct Astro 5/Vite 6 pattern.
- **Client-side JS** lives in `<script>` tags inside `.astro` pages. Astro bundles and deduplicates these automatically. Use `<script is:inline>` only when referencing external globals (e.g. Leaflet's `L`).
- **Named slots** for ToolLayout: `form`, `results`, `head`. Example: `<div slot="form">...</div>`
- **No client-side framework** — all interactivity is vanilla JS calling `/api/*` endpoints via `fetch()`.

## API Endpoints

All return JSON. Errors in Spanish. Validated server-side.

| Route | Method | Params | Backend |
|-------|--------|--------|---------|
| `/api/dns` | GET | `domain` (required), `type` (default: A) | Cloudflare DoH (`cloudflare-dns.com/dns-query`) |
| `/api/email-auth` | GET | `domain` (required) | 3 DoH lookups (SPF + DMARC + DKIM selectors in parallel) |
| `/api/geoip` | GET | `ip` (optional — omit to detect visitor IP) | `ip-api.com` (HTTP, free tier) |

## Brand & UI Rules

- **Colors:** Verde `#10B981`, Turquesa `#6EE7B7`, Gris oscuro `#1F2937`, Fondo `#F8FAF9`
- **Fonts:** Inter (400/500/600/700) for UI, JetBrains Mono for code/results
- **Wordmark:** `delzo.cloud / tools` — "delzo" bold dark, ".cloud" regular green, "/" light gray, "tools" medium gray
- **Language:** All UI text in Spanish (Argentine vos dialect). Use "consultá", "ingresá", "verificá" (not "consulta", "ingresa"). Respect accents: "migración", "dirección", "autenticación".
- **Errors in Spanish:** "Dominio inválido.", "Ingresá un dominio.", "Error de conexión. Intentá de nuevo."
- **Status badges:** `.badge-pass` (green), `.badge-warning` (amber), `.badge-fail` (red) — defined in `global.css`
- **No emojis in code** — only in ToolCard icons on homepage

## Adding a New Tool

1. Create `src/pages/mi-tool.astro` using `ToolLayout` component
2. If it needs an API: create `src/pages/api/mi-tool.ts` with `export const prerender = false;`
3. Add the tool to the `tools` array in `src/components/Header.astro` (nav links)
4. Add a `ToolCard` entry in `src/pages/index.astro` (homepage grid)
5. Run `npm run build` to verify

## Deploy

```bash
npm run deploy    # Builds + deploys to Cloudflare Workers
```

Cloudflare Dashboard setup:
1. Workers → verify `delzo-tools` is deployed
2. DNS of `delzo.cloud` → CNAME `tools` → Worker
3. Workers → Custom domains → `tools.delzo.cloud`

## External Dependencies (no API keys needed)

- **Cloudflare DoH** (`cloudflare-dns.com/dns-query`) — DNS queries via HTTPS, JSON format
- **ip-api.com** — Free IP geolocation (HTTP only on free tier, 45 req/min limit)
- **Leaflet.js** (CDN) + OpenStreetMap tiles — Map rendering, loaded in `ip-geolocation.astro` head
- **Google Fonts** — Inter + JetBrains Mono

## Related Repos

- `delzocloud/delzo-marketing` — Brand strategy, product catalog, financial plan, content scripts
