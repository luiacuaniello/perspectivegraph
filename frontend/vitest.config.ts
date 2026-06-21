import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Vitest config, kept out of the production `tsc -b` (excluded in tsconfig) so a
// type mismatch between vite 8's rolldown types and vitest's bundled vite types
// never blocks the build. Tests are validated by running them, not by tsc.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: "./src/test/setup.ts",
    css: false,
  },
});
