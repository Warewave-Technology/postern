/// <reference types="vitest/config" />
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

  // Testler jsdom'da koşuyor: gerçek bir tarayıcı değil ama bu
  // paketteki iddiaların hepsi DOM ve durum makinesi hakkında —
  // "yükleniyor ile boş ayrı ekranlar mı", "hata temizleniyor mu",
  // "yıkıcı işlem onay istiyor mu". Bunlar için tarayıcı gerekmiyor
  // ve gerektirmek testleri koşulmaz hâle getirirdi.
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    globals: true,
    css: true,
  },
});
