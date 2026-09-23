import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// 개발 서버: /api 요청을 로컬 FastAPI(8000)로 넘긴다. 운영은 nginx.conf에서 같은 역할을 한다.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
  },
})
