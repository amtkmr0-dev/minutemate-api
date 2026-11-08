import { defineConfig } from "vitest/config";

export default defineConfig({
  envDir: false,
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    setupFiles: ["./tests/setup.ts"],
    maxWorkers: 2,
    fileParallelism: true,
    testTimeout: 15_000,
    hookTimeout: 30_000,
  },
});
