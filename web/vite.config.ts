/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The production bundle is embedded into the Go binary (internal/platform/webui).
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../internal/platform/webui/dist/app",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/health": "http://127.0.0.1:8080",
    },
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
    allowOnly: false,
    passWithNoTests: false,
    restoreMocks: true,
  },
});
