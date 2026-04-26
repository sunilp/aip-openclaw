import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    poolOptions: {
      forks: {
        execArgv: ["--experimental-wasm-modules"],
      },
    },
  },
});
