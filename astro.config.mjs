import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  adapter: cloudflare(),
  site: 'https://tools.delzo.cloud',
  // One URL per page, without trailing slash (/email-auth, not /email-auth/).
  trailingSlash: 'never',
  build: { format: 'file' },
  integrations: [sitemap({ filter: (page) => !page.includes('/404') })],
});
