import { execFileSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";

// Global setup: provision a fresh, isolated test SQLite database and apply the
// Prisma schema via `prisma db push` before any test runs. Runs once.
const ROOT = resolve(__dirname, "..");
const TEST_DB_PATH = resolve(ROOT, "prisma", "test.db");
const DATABASE_URL = process.env.DATABASE_URL ?? `file:${TEST_DB_PATH}`;

export default function setup() {
  // Start from a clean slate so test counts are deterministic.
  for (const suffix of ["", "-journal", "-wal", "-shm"]) {
    const f = `${TEST_DB_PATH}${suffix}`;
    if (existsSync(f)) rmSync(f);
  }

  const env = { ...process.env, DATABASE_URL, CI: "1" };

  // Ensure the client is generated, then push the schema to the test DB.
  execFileSync("npx", ["prisma", "generate"], {
    cwd: ROOT,
    env,
    stdio: "inherit",
  });
  // We delete the test DB file above, so a plain `db push` recreates the
  // schema from scratch on a fresh file. We deliberately avoid `--force-reset`
  // (a destructive operation that Prisma guards against in agent contexts);
  // it is unnecessary here because the file is already gone.
  execFileSync("npx", ["prisma", "db", "push"], {
    cwd: ROOT,
    env,
    stdio: "inherit",
  });
}
