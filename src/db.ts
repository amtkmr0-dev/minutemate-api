/**
 * MinuteMate API — database connection (Drizzle ORM + Neon serverless).
 *
 * Uses the Neon HTTP driver (@neondatabase/serverless), which works on any
 * Node runtime including serverless — no persistent TCP pool needed.
 */

import { drizzle } from "drizzle-orm/neon-http";
import { neon } from "@neondatabase/serverless";
import * as schema from "./schema.js";

function resolveDatabaseUrl(): string {
  const url = process.env.DATABASE_URL;
  if (url && url.trim().length > 0) return url.trim();
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "FATAL: DATABASE_URL is not set. Set it to your Neon Postgres connection string.",
    );
  }
  // Dev fallback: lets `npm run dev` boot without a database for route
  // wiring checks. Any DB-touching route will fail with a clear error.
  console.warn("[db] DATABASE_URL is not set — using a placeholder. DB routes will fail until it is set.");
  return "postgresql://dev:dev@localhost:5432/dev";
}

const sql = neon(resolveDatabaseUrl());

/** Drizzle client with the full schema attached. */
export const db = drizzle(sql, { schema });

export type Db = typeof db;
