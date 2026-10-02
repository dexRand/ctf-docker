import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// In production the built SPA is served by FastAPI from the same origin.
// In dev, proxy API + WebSocket to the backend on :19014.
export default defineConfig({
  plugins: [vue()],
  build: { outDir: 'dist', emptyOutDir: true },
  server: {
    port: 5174,
    proxy: {
      '/api': 'http://localhost:19014',
      '/ws': { target: 'ws://localhost:19014', ws: true },
    },
  },
})
