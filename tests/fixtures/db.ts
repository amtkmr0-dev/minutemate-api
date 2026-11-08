import { PGlite } from "@electric-sql/pglite";
import { is, SQL } from "drizzle-orm";
import { drizzle } from "drizzle-orm/pglite";
import { getTableConfig, PgDialect, PgTable } from "drizzle-orm/pg-core";
import * as schema from "../../src/schema.js";

// A real, in-memory PostgreSQL engine. No Neon URL, sockets, migrations or seeds.
export const postgres = new PGlite();
export const db = drizzle(postgres, { schema });
export async function sql(query: string, params: unknown[] = []) {
  return (await postgres.query(query, params)).rows;
}

const quote = (name: string) => `"${name.replaceAll('"', '""')}"`;
const tables: unknown[] = Object.values(schema);
const configs = tables
  .filter((value): value is PgTable => is(value, PgTable))
  .map(getTableConfig);

export async function initializeDatabase() {
  const dialect = new PgDialect();
  // Derive test DDL from the shipped schema; do not duplicate a drifting schema.
  for (const config of configs) {
    const columns = config.columns.map((column) => {
      let definition = `${quote(column.name)} ${column.getSQLType()}`;
      if (column.notNull) definition += " NOT NULL";
      if (column.primary) definition += " PRIMARY KEY";
      if (column.isUnique) definition += " UNIQUE";
      if (column.default !== undefined) {
        const value = column.default;
        definition += " DEFAULT " + (is(value, SQL)
          ? dialect.sqlToQuery(value).sql
          : typeof value === "string" ? `'${value.replaceAll("'", "''")}'` : String(value));
      }
      return definition;
    });
    await postgres.exec(`CREATE TABLE ${quote(config.name)} (${columns.join(", ")})`);
  }
  // Add FKs only after every referenced table exists.
  for (const config of configs) {
    for (const fk of config.foreignKeys) {
      const reference = fk.reference();
      await postgres.exec(`ALTER TABLE ${quote(config.name)} ADD FOREIGN KEY
        (${reference.columns.map((c) => quote(c.name)).join(", ")})
        REFERENCES ${quote(getTableConfig(reference.foreignTable).name)}
        (${reference.foreignColumns.map((c) => quote(c.name)).join(", ")})
        ON DELETE ${fk.onDelete ?? "no action"}`);
    }
  }
  // The startup DDL supplies these composite constraints in the recovered API.
  await postgres.exec("CREATE UNIQUE INDEX chat_threads_pair_uidx ON chat_threads(user_id, creator_id)");
  await postgres.exec("CREATE UNIQUE INDEX blocks_pair_uidx ON blocks(blocker_id, blocked_id)");
}

export async function resetDatabase() {
  await postgres.exec(`TRUNCATE ${configs.map((config) => quote(config.name)).join(", ")} CASCADE`);
}
