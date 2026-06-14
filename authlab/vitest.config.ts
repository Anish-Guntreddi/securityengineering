import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// AuthLab Vitest configuration.
//
// - The `@/*` import alias mirrors tsconfig so route modules resolve.
// - globalSetup provisions an ISOLATED test SQLite database and runs
//   `prisma db push` against it before any test file executes.
// - setupFiles ensures every worker has DATABASE_URL pointed at that test DB.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "."),
    },
  },
  test: {
    environment: "node",
    globals: true,
    globalSetup: ["./tests/global-setup.ts"],
    setupFiles: ["./tests/setup-env.ts"],
    // Run serially against the shared test SQLite file to avoid write races.
    // (Vitest 4 flattened poolOptions to top-level options.)
    fileParallelism: false,
    pool: "forks",
    maxWorkers: 1,
  },
});
