import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

// Flat config for the React + TypeScript + Vite dashboard. Type-aware linting is off
// (fast, no project service) - `tsc -b` in `npm run build` already does the deep type
// check; ESLint here catches the logic/hooks/hygiene issues tsc does not.
export default tseslint.config(
  { ignores: ["dist", "coverage", "*.config.js", "*.config.ts"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // Two react-hooks v6 rules fire on deliberate, idiomatic patterns already in the
      // code (the "latest ref written during render" in GraphCanvas, and the debounced
      // search resetting state inside its own effect). They are not bugs, so keep them as
      // warnings (visible, tracked) rather than blocking - revisit if we adopt the compiler.
      "react-hooks/refs": "warn",
      "react-hooks/set-state-in-effect": "warn",
    },
  },
);
