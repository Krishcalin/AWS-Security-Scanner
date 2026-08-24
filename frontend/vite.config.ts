import { defineConfig, loadEnv, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// The shipped console's DATA MODE is a build-time decision that leaves no
// readable trace in dist/. With VITE_DATA_SOURCE unset, client.ts falls back to
// 'sample': the bundle reads fixtures instead of the API and contains no
// authentication code at all - no login, and no Log out control, because
// UserMenu renders nothing outside live mode. That is a demo wearing the
// product's filename, and a plain `npm run build` produces it silently.
//
// Stamping the resolved mode into the bundle makes the artifact self-describing,
// so a test can refuse to ship the wrong one.
function stampDataMode(dataMode: string): Plugin {
  return {
    name: 'overwatch:stamp-data-mode',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'build-info.json',
        source: JSON.stringify({ data_mode: dataMode }, null, 2) + '\n',
      })
    },
  }
}

// Dev: the SPA runs on Vite; API calls to /api are proxied to the FastAPI hub on :8000.
// Prod: `npm run build` emits dist/, which FastAPI serves via a StaticFiles mount.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const dataMode = process.env.VITE_DATA_SOURCE ?? env.VITE_DATA_SOURCE ?? 'sample'
  return {
  plugins: [react(), tailwindcss(), stampDataMode(dataMode)],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/api/, ''),
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
  }
})
