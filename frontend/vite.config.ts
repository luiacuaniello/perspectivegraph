import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dashboard talks to the Go GraphQL BFF. In dev we proxy /graphql to it so
// the browser sees a same-origin request (no CORS surprises).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/graphql": {
        target: process.env.AEGIS_API ?? "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
