import { defineConfig } from "vite";

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: {
      polyfill: false,
    },
    target: "es2022",
  },
  preview: {
    host: "127.0.0.1",
    port: 4173,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: false,
  },
});
