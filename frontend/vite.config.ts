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
      // Everything below was missing, and the failure is silent in a way that wastes an
      // afternoon: an unproxied path falls through to the SPA, so the browser gets
      // index.html with a 200 and the fetch dies on `Unexpected token '<'`. The nginx
      // config that serves the built app already proxies all of these - dev and prod
      // must expose the same surface, or a feature works in the container and not on
      // the machine it was written on.
      //
      // Red-team / BAS verdict board, read by the trust page.
      "/validations": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // How the SPA learns whether to show the login gate, and for SSO the IdP's
      // coordinates.
      "/auth/config": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // AI assistant (summary / query / explain).
      "/ai": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
      // Remediation-as-PR.
      "/remediation": {
        target: process.env.PERSPECTIVE_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
