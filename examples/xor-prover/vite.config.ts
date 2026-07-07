import { defineConfig } from 'vite';

// Cross-origin isolation headers — required for SharedArrayBuffer, which the
// threaded wasm variants need.
const coopCoep = {
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

export default defineConfig({
  server: { headers: coopCoep, allowedHosts: ['.trycloudflare.com'] },
  preview: { headers: coopCoep },
  
  optimizeDeps: {
    exclude: ['@reilabs/sunspot_js'],
  },
  worker: {
    format: 'es',
  },
});
