import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  root: "web",
  build: {
    assetsInlineLimit: 0,
    emptyOutDir: true,
    manifest: true,
    outDir: "../dist",
    sourcemap: false,
    target: "es2022",
  },
  worker: {
    format: "es",
  },
  preview: {
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
  },
});
