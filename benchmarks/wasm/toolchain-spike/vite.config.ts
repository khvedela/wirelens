import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  plugins: [react()],
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
});
