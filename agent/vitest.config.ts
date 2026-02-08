import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["../tests/agent/**/*.test.ts"],
    globals: true,
  },
});
