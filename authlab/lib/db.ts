import { PrismaBetterSqlite3 } from "@prisma/adapter-better-sqlite3";
import { PrismaClient } from "../app/generated/prisma/client";

/**
 * Prisma client singleton.
 *
 * Uses the better-sqlite3 driver adapter (Prisma 7 driver-adapter model).
 * The connection URL comes from DATABASE_URL so tests can point at an
 * isolated SQLite file; otherwise we fall back to the local dev database.
 *
 * To switch to PostgreSQL: replace PrismaBetterSqlite3 with PrismaPg from
 * `@prisma/adapter-pg`, set DATABASE_URL to your Postgres URL, and flip the
 * datasource provider in prisma/schema.prisma.
 */

const databaseUrl = process.env.DATABASE_URL ?? "file:./prisma/dev.db";

function createPrismaClient(): PrismaClient {
  const adapter = new PrismaBetterSqlite3({ url: databaseUrl });
  return new PrismaClient({ adapter });
}

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma: PrismaClient =
  globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.prisma = prisma;
}

export default prisma;
