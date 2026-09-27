import { defineConfig } from "drizzle-kit";

export default defineConfig({
  schema: "./src/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    // drizzle-kit reads the URL from the environment at runtime.
    url: process.env.DATABASE_URL || "postgresql://dev:dev@localhost:5432/dev",
  },
});
