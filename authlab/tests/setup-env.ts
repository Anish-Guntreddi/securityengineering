// Per-worker environment setup. Ensures DATABASE_URL points at the isolated
// test SQLite database before any module (notably lib/db.ts) is imported.
import { resolve } from "node:path";

const TEST_DB_PATH = resolve(__dirname, "..", "prisma", "test.db");

if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = `file:${TEST_DB_PATH}`;
}
// Vitest sets NODE_ENV to "test" automatically; we deliberately do not
// reassign it here (it is typed read-only in the Next.js build environment).
