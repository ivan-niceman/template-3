// @ts-check
import { defineConfig } from 'astro/config';
import vercel from '@astrojs/vercel';
import autoprefixer from 'autoprefixer';

// https://astro.build/config
export default defineConfig({
  base: '/',
  site: 'https://template-3-inky.vercel.app/',
  output: 'server',
  adapter: vercel(),
  vite: {
    css: {
      postcss: {
        plugins: [autoprefixer()],
      },
    },
  },
});
