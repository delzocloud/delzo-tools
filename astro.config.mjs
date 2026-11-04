import { defineConfig, envField } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  // The site uses neither astro:assets nor sessions. Without these two options the
  // adapter injects an IMAGES binding and a SESSION KV namespace that wrangler would
  // auto-provision on deploy (new resources plus extra API token permissions).
  adapter: cloudflare({ imageService: 'passthrough' }),
  session: false,
  site: 'https://tools.delzo.cloud',
  env: {
    schema: {
      // Worker secret, uploaded by CI from the GitHub secret of the same name. Local: .dev.vars.
      // Optional: without it /api/geoip falls back to ipwho.is.
      IPGEOLOCATION_API_KEY: envField.string({ context: 'server', access: 'secret', optional: true }),
    },
  },
  // One URL per page, without trailing slash (/email-auth, not /email-auth/).
  trailingSlash: 'never',
  build: { format: 'file' },
  integrations: [sitemap({ filter: (page) => !page.includes('/404') })],
});
