import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  // The site uses neither astro:assets nor sessions. Without these two options the
  // adapter injects an IMAGES binding and a SESSION KV namespace that wrangler would
  // auto-provision on deploy (new resources plus extra API token permissions).
  adapter: cloudflare({ imageService: 'passthrough' }),
  session: false,
  site: 'https://tools.delzo.cloud',
  // One URL per page, without trailing slash (/email-auth, not /email-auth/).
  trailingSlash: 'never',
  build: { format: 'file' },
  integrations: [sitemap({ filter: (page) => !page.includes('/404') })],
});
