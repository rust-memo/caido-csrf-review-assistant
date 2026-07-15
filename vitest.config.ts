import vue from "@vitejs/plugin-vue";
import path from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "packages/frontend/src"),
    },
  },
  test: {
    environmentMatchGlobs: [
      ["packages/frontend/src/**/*.test.ts", "happy-dom"],
    ],
    coverage: {
      provider: "v8",
      include: [
        "packages/backend/src/analyzer.ts",
        "packages/backend/src/context.ts",
        "packages/backend/src/message.ts",
        "packages/backend/src/poc.ts",
        "packages/backend/src/report.ts",
        "packages/backend/src/store.ts",
        "packages/backend/src/variants.ts",
        "packages/frontend/src/utils.ts",
        "packages/frontend/src/components/**/*.vue",
      ],
      reporter: ["text", "json-summary"],
      thresholds: {
        statements: 80,
        branches: 70,
        functions: 80,
        lines: 80,
      },
    },
  },
});
