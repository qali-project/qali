import js from "@eslint/js";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: ["src/generated/**", "playwright-report/**", "test-results/**", "node_modules/**"],
  },
  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      globals: { ...globals.browser },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { "react-hooks": reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      // Backend access goes through the generated client (AGENTS.md).
      "no-restricted-globals": [
        "error",
        { name: "fetch", message: "Use the generated API client in src/api/client.ts." },
      ],
    },
  },
  {
    files: ["src/api/client.ts", "src/**/*.test.{ts,tsx}"],
    rules: { "no-restricted-globals": "off" },
  },
  {
    files: ["eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
