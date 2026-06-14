import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // better-sqlite3 is a native module; keep it external to the server bundle so
  // Next.js does not try to bundle the .node binary. The Prisma packages are
  // also kept external for correct native-engine resolution.
  serverExternalPackages: ["better-sqlite3", "@prisma/client", "prisma"],
};

export default nextConfig;
