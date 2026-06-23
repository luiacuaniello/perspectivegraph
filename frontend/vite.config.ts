import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the Go GraphQL BFF. In dev we proxy /graphql to it so
// the browser sees a same-origin request (no CORS surprises). Test config lives
// in vitest.config.ts (kept separate so this build config stays vite-typed).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/graphql": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // Downloadable exports (SIEM NDJSON, OSCAL) - same-origin in dev too.
      "/export": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // Triage/suppression REST board.
      "/suppressions": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // Remediation ticketing REST board.
      "/tickets": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
