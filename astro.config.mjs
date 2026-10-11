// @ts-check
import { defineConfig } from 'astro/config';
import node from '@astrojs/node';
import vercel from '@astrojs/vercel';
import purgecss from 'astro-purgecss';

const isVercel = Boolean(process.env.VERCEL);

// https://astro.build/config
export default defineConfig({
  build: {
    inlineStylesheets: 'never', // Отключает инлайнинг CSS
  },
  output: 'server',
  adapter: isVercel
    ? vercel()
    : node({
        mode: 'standalone',
      }),
  integrations: [purgecss()],
});
