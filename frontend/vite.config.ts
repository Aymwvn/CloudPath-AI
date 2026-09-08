import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      // matches ARCHITECTURE.md Section 27's API prefix — lets the dev
      // server proxy to the FastAPI backend without CORS config
      '/api': 'http://localhost:8000',
    },
  },
})
