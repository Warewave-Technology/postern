import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// dev sunucusu (npm run dev) API'yi gerçek postern'e yönlendirir:
// frontend'i hot-reload ile geliştirirken backend 8088'de çalışır durur.
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8088",
      "/auth": "http://127.0.0.1:8088",
    },
  },
  build: { outDir: "dist" },
});
