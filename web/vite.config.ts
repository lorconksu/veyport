import fs from 'fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

const apiProxyTarget = process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:8080'
const httpsKeyFile = process.env.VITE_HTTPS_KEY_FILE
const httpsCertFile = process.env.VITE_HTTPS_CERT_FILE
const httpsConfig = httpsKeyFile && httpsCertFile
  ? {
      key: fs.readFileSync(httpsKeyFile),
      cert: fs.readFileSync(httpsCertFile),
    }
  : undefined

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    sourcemap: false,
  },
  server: {
    https: httpsConfig,
    proxy: {
      '/api': {
        target: apiProxyTarget,
        changeOrigin: true,
      },
    },
  },
})
