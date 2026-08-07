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
      // Two react-hooks v6 rules are enabled explicitly. Only one of them currently
      // fires: set-state-in-effect, on the debounced search clearing its own state inside
      // its effect, which is deliberate (nothing it clears is in the effect's
      // dependencies, so it cannot re-enter) and is disabled on that exact line with the
      // reasoning beside it. refs fires nowhere today and is listed so that enabling it
      // stays a decision rather than an accident of what the recommended set contains.
      //
      // They stay at "warn" rather than "error" because the distinction still helps when
      // reading output locally. It is NOT a softer gate: `npm run lint` runs with
      // --max-warnings=0, so a warning fails the build exactly as an error would. What the
      // level buys is that a genuine future violation surfaces as something to judge,
      // rather than as a rule someone is tempted to switch off wholesale.
      "react-hooks/refs": "warn",
      "react-hooks/set-state-in-effect": "warn",
    },
  },
);
