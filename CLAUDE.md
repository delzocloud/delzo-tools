# CLAUDE.md — delzo-tools

## Project Overview

Free networking tools site for **delzo.cloud** ("engineering as marketing"). Targets IT professionals at Latin American SMEs.

- **Domain:** `tools.delzo.cloud`
- **Stack:** Astro 5 (hybrid mode) + Cloudflare Workers
- **Language:** Spanish (Argentine vos dialect) for UI, English for code

## Commands

```bash
npm run dev       # Local dev server
npm run build     # Build for production
npm run preview   # Preview production build
npm run deploy    # Build + wrangler deploy
```

## Architecture

- **Pages:** `src/pages/*.astro` (static) + `src/pages/api/*.ts` (server endpoints)
- **Lib:** `src/lib/` — pure functions for DNS, CIDR, email parsing
- **Components:** `src/components/` — Astro components (Header, Footer, ToolLayout, etc.)
- **Styles:** `src/styles/global.css` — CSS variables matching delzo.cloud brand

## API Endpoints (server-rendered)

| Route | Params | Notes |
|-------|--------|-------|
| `/api/dns` | `domain`, `type` | Cloudflare DoH |
| `/api/email-auth` | `domain` | SPF + DMARC + DKIM analysis |
| `/api/geoip` | `ip` (optional) | ip-api.com, auto-detect visitor IP |

## Brand

- Verde: `#10B981`, Turquesa: `#6EE7B7`, Gris oscuro: `#1F2937`
- Font: Inter (Google Fonts) + JetBrains Mono for code
- Wordmark: `delzo.cloud / tools`
