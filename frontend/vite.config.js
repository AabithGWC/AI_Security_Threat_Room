import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/chat': 'http://127.0.0.1:8002',
      '/ping': 'http://127.0.0.1:8002',
      '/security': 'http://127.0.0.1:8002',
      '/auditor': 'http://127.0.0.1:8002',
      '/reset': 'http://127.0.0.1:8002',
      '/session': 'http://127.0.0.1:8002',
    },
  },
});
