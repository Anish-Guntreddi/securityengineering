import { defineConfig } from "prisma/config";

// AuthLab Prisma CLI config.
//
// The datasource URL lives here (Prisma 7 convention) and is used by the CLI
// for `prisma db push`. We default to a local SQLite file but honour
// DATABASE_URL so the test setup can point at an isolated test database.
//
// To switch to PostgreSQL: set DATABASE_URL to your Postgres connection string
// and change `provider` to "postgresql" in prisma/schema.prisma.
export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: {
    url: process.env.DATABASE_URL ?? "file:./prisma/dev.db",
  },
});
