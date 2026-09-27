/**
 * MinuteMate API — database schema (Drizzle ORM, Postgres/Neon).
 *
 * Money is stored in PAISE as integers everywhere in the database — never
 * floats — so wallet math is exact. The API converts to rupees only at the
 * response boundary, because the mobile client formats balances as ₹.
 */

import { pgTable, text, bigint, timestamp, boolean, index } from "drizzle-orm/pg-core";

/** App users. One row per verified phone number. */
export const users = pgTable("users", {
  id: text("id").primaryKey(), // uuid
  phone: text("phone").notNull().unique(), // normalized 10-digit Indian mobile
  name: text("name"),
  email: text("email"),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

/**
 * Wallet ledger header — one row per user.
 * balancePaise is the single source of truth for the user's spendable balance.
 */
export const wallets = pgTable("wallets", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  /** Spendable balance, integer paise. Never negative. */
  balancePaise: bigint("balance_paise", { mode: "number" }).notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Wallet = typeof wallets.$inferSelect;

/** Every wallet movement — recharges, call debits, refunds. Append-only. */
export const transactions = pgTable(
  "transactions",
  {
    id: text("id").primaryKey(), // uuid
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    /** 'recharge' | 'call_debit' | 'refund' | 'bonus' */
    type: text("type").notNull(),
    /** Signed amount, integer paise. Positive = credit, negative = debit. */
    amountPaise: bigint("amount_paise", { mode: "number" }).notNull(),
    /** Bonus portion of a recharge, integer paise. 0 for non-recharge types. */
    bonusPaise: bigint("bonus_paise", { mode: "number" }).notNull().default(0),
    /** Balance after this transaction, integer paise — makes audits trivial. */
    balanceAfterPaise: bigint("balance_after_paise", { mode: "number" }).notNull(),
    /** Razorpay payment id (pay_...) when this came from a payment. */
    providerPaymentId: text("provider_payment_id"),
    /** Razorpay order id (order_...) for recharge transactions. */
    providerOrderId: text("provider_order_id"),
    /** Human-readable description for the statement screen. */
    description: text("description"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("transactions_user_created_idx").on(t.userId, t.createdAt)],
);

export type Transaction = typeof transactions.$inferSelect;

/**
 * Pending recharge orders — created at /create-order, consumed at /verify.
 * The SERVER is the source of truth for userId + amount; the client never
 * supplies either at verify time. Rows are deleted (or marked used) on verify.
 */
export const pendingOrders = pgTable(
  "pending_orders",
  {
    /** Razorpay order id (order_...) — or SIM_... in simulation mode. */
    orderId: text("order_id").primaryKey(),
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    packId: text("pack_id").notNull(),
    amountPaise: bigint("amount_paise", { mode: "number" }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    /** Orders expire after 30 minutes if never verified. */
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => [index("pending_orders_user_idx").on(t.userId)],
);

export type PendingOrder = typeof pendingOrders.$inferSelect;

/**
 * OTP challenges. Only the SHA-256 hash is stored — never the plain OTP.
 * One active row per phone; sending a new OTP replaces the old one.
 */
export const otps = pgTable("otps", {
  phone: text("phone").primaryKey(), // normalized 10-digit mobile
  otpHash: text("otp_hash").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  attempts: bigint("attempts", { mode: "number" }).notNull().default(0),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});

export type Otp = typeof otps.$inferSelect;

/**
 * Refresh-token allowlist. Logout deletes the row; rotation replaces the jti.
 * Access tokens are stateless (15 min) — only refresh tokens are tracked.
 */
export const refreshTokens = pgTable(
  "refresh_tokens",
  {
    jti: text("jti").primaryKey(), // jwt id
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("refresh_tokens_user_idx").on(t.userId)],
);

/** Idempotency record — every successfully verified Razorpay payment id, once. */
export const processedPayments = pgTable("processed_payments", {
  providerPaymentId: text("provider_payment_id").primaryKey(), // pay_...
  userId: text("user_id").notNull(),
  orderId: text("order_id").notNull(),
  amountPaise: bigint("amount_paise", { mode: "number" }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
});
