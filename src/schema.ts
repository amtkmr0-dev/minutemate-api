/**
 * MinuteMate API — database schema (Drizzle ORM, Postgres/Neon).
 *
 * Money is stored in PAISE as integers everywhere in the database — never
 * floats — so wallet math is exact. The API converts to rupees only at the
 * response boundary, because the mobile client formats balances as ₹.
 */

import { pgTable, text, bigint, timestamp, boolean, index, integer, customType } from "drizzle-orm/pg-core";

/** Postgres bytea column type for Drizzle (used for APK binaries). */
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return "bytea";
  },
});

/** App users. One row per verified phone number. */
export const users = pgTable("users", {
  id: text("id").primaryKey(), // uuid
  phone: text("phone").notNull().unique(), // normalized 10-digit Indian mobile
  name: text("name"),
  email: text("email"),
  /** 'user' | 'creator' | 'agency' | 'admin'. Defaults to 'user'; creators upgrade via apply/onboarding. */
  role: text("role").notNull().default("user"),
  /** 'active' | 'banned'. Banned accounts cannot auth or transact. */
  status: text("status").notNull().default("active"),
  /** Profile picture (data URL, trial mode). */
  avatarUrl: text("avatar_url"),
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

/* ------------------------------------------------------------------ */
/* Creators                                                            */
/* ------------------------------------------------------------------ */

/**
 * Creator public profile — one row per user with role='creator'.
 * Money in paise integers, same as wallets.
 */
export const creatorProfiles = pgTable(
  "creator_profiles",
  {
    userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
    displayName: text("display_name").notNull(),
    bio: text("bio"),
    /** Languages as comma-separated list, e.g. "Hindi,English". */
    languages: text("languages").notNull().default("Hindi,English"),
    /** Price per minute in paise. */
    pricePerMinPaise: bigint("price_per_min_paise", { mode: "number" }).notNull().default(2000),
    avatarUrl: text("avatar_url"),
    /** JSON array of media image URLs. */
    mediaUrls: text("media_urls").notNull().default("[]"),
    introVideoUrl: text("intro_video_url"),
    /** 'audio' | 'video' | 'both' */
    allowedCallTypes: text("allowed_call_types").notNull().default("both"),
    /** 'pending' | 'approved' | 'rejected'. Only approved creators are listed. */
    verificationStatus: text("verification_status").notNull().default("pending"),
    /** 'pending' | 'verified' | 'rejected' — KYC document review state. */
    kycStatus: text("kyc_status").notNull().default("pending"),
    isOnline: boolean("is_online").notNull().default(false),
    randomMatchEnabled: boolean("random_match_enabled").notNull().default(true),
    rating: integer("rating").notNull().default(0), // avg rating * 10, e.g. 45 = 4.5
    ratingCount: integer("rating_count").notNull().default(0),
    totalCalls: integer("total_calls").notNull().default(0),
    totalMinutes: integer("total_minutes").notNull().default(0),
    /** Agency that manages this creator, if any (users.id of agency account). */
    agencyId: text("agency_id"),
    talksAbout: text("talks_about").notNull().default("[]"), // JSON array
    hobbies: text("hobbies").notNull().default("[]"), // JSON array
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("creator_profiles_online_idx").on(t.isOnline, t.verificationStatus),
    index("creator_profiles_agency_idx").on(t.agencyId),
  ],
);

export type CreatorProfile = typeof creatorProfiles.$inferSelect;
export type NewCreatorProfile = typeof creatorProfiles.$inferInsert;

/** Creator earnings wallet — separate from the user spending wallet. */
export const creatorWallets = pgTable("creator_wallets", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  /** Lifetime earnings available for withdrawal, integer paise. */
  balancePaise: bigint("balance_paise", { mode: "number" }).notNull().default(0),
  /** Lifetime gross earnings, integer paise. */
  lifetimePaise: bigint("lifetime_paise", { mode: "number" }).notNull().default(0),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** Creator bank/UPI payout details. */
export const creatorBankDetails = pgTable("creator_bank_details", {
  userId: text("user_id").primaryKey().references(() => users.id, { onDelete: "cascade" }),
  accountHolder: text("account_holder"),
  accountNumber: text("account_number"),
  ifsc: text("ifsc"),
  upiId: text("upi_id"),
  updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
});

/** KYC document submissions. Files stored as data URLs (trial scale). */
export const kycSubmissions = pgTable(
  "kyc_submissions",
  {
    id: text("id").primaryKey(), // uuid
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    /** 'aadhaar' | 'pan' | 'selfie' | 'video' */
    docType: text("doc_type").notNull(),
    /** data URL or remote URL of the document. */
    docUrl: text("doc_url").notNull(),
    /** 'pending' | 'approved' | 'rejected' */
    status: text("status").notNull().default("pending"),
    reviewerNote: text("reviewer_note"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    reviewedAt: timestamp("reviewed_at", { withTimezone: true }),
  },
  (t) => [index("kyc_submissions_user_idx").on(t.userId)],
);

/* ------------------------------------------------------------------ */
/* Blocks                                                              */
/* ------------------------------------------------------------------ */

/** Users blocking creators (and creators blocking users). Persistent. */
export const blocks = pgTable(
  "blocks",
  {
    blockerId: text("blocker_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    blockedId: text("blocked_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("blocks_blocker_idx").on(t.blockerId)],
);

/* ------------------------------------------------------------------ */
/* Chat                                                                */
/* ------------------------------------------------------------------ */

/** One thread per (user, creator) pair. */
export const chatThreads = pgTable(
  "chat_threads",
  {
    id: text("id").primaryKey(), // uuid
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    creatorId: text("creator_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    lastMessageAt: timestamp("last_message_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("chat_threads_user_idx").on(t.userId, t.lastMessageAt),
    index("chat_threads_creator_idx").on(t.creatorId, t.lastMessageAt),
  ],
);

export type ChatThread = typeof chatThreads.$inferSelect;

/** Chat messages. Append-only. */
export const chatMessages = pgTable(
  "chat_messages",
  {
    id: text("id").primaryKey(), // uuid
    threadId: text("thread_id").notNull().references(() => chatThreads.id, { onDelete: "cascade" }),
    senderId: text("sender_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    /** 'user' | 'creator' */
    senderRole: text("sender_role").notNull(),
    body: text("body").notNull(),
    /** 'text' | 'gift' — gift messages carry a giftId. */
    kind: text("kind").notNull().default("text"),
    giftId: text("gift_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("chat_messages_thread_idx").on(t.threadId, t.createdAt)],
);

export type ChatMessage = typeof chatMessages.$inferSelect;

/* ------------------------------------------------------------------ */
/* Calls                                                               */
/* ------------------------------------------------------------------ */

/**
 * Call sessions — persistent lifecycle: ringing -> active -> ended/missed/rejected.
 * Billing: costPaise computed at end from durationSec * creator rate.
 */
export const callSessions = pgTable(
  "call_sessions",
  {
    id: text("id").primaryKey(), // uuid
    userId: text("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    creatorId: text("creator_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    /** Zego room id — both sides join this room. */
    roomId: text("room_id").notNull(),
    /** 'audio' | 'video' */
    callType: text("call_type").notNull().default("video"),
    /** 'ringing' | 'active' | 'ended' | 'rejected' | 'missed' | 'cancelled' */
    status: text("status").notNull().default("ringing"),
    /** Rate locked at call start, paise per minute. */
    ratePaisePerMin: bigint("rate_paise_per_min", { mode: "number" }).notNull().default(0),
    durationSec: integer("duration_sec").notNull().default(0),
    /** Actual billed amount, paise. 0 until ended. */
    costPaise: bigint("cost_paise", { mode: "number" }).notNull().default(0),
    lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
    startedAt: timestamp("started_at", { withTimezone: true }),
    endedAt: timestamp("ended_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    index("call_sessions_user_idx").on(t.userId, t.createdAt),
    index("call_sessions_creator_idx").on(t.creatorId, t.createdAt),
    index("call_sessions_status_idx").on(t.status, t.createdAt),
  ],
);

export type CallSession = typeof callSessions.$inferSelect;

/* ------------------------------------------------------------------ */
/* Gifts                                                               */
/* ------------------------------------------------------------------ */

/** Gift catalog. */
export const gifts = pgTable("gifts", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  /** Emoji/icon rendered client-side. */
  emoji: text("emoji").notNull(),
  /** Price in paise (debited from user wallet, credited to creator earnings). */
  pricePaise: bigint("price_paise", { mode: "number" }).notNull(),
  sortOrder: integer("sort_order").notNull().default(0),
});

/** Gift send ledger. Append-only. */
export const giftTransactions = pgTable(
  "gift_transactions",
  {
    id: text("id").primaryKey(), // uuid
    fromUserId: text("from_user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    toCreatorId: text("to_creator_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    giftId: text("gift_id").notNull().references(() => gifts.id),
    pricePaise: bigint("price_paise", { mode: "number" }).notNull(),
    callSessionId: text("call_session_id"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("gift_transactions_creator_idx").on(t.toCreatorId, t.createdAt)],
);

/* ------------------------------------------------------------------ */
/* Withdrawals                                                         */
/* ------------------------------------------------------------------ */

/** Creator payout requests. */
export const withdrawals = pgTable(
  "withdrawals",
  {
    id: text("id").primaryKey(), // uuid
    creatorId: text("creator_id").notNull().references(() => users.id, { onDelete: "cascade" }),
    amountPaise: bigint("amount_paise", { mode: "number" }).notNull(),
    /** Snapshot of payout destination at request time. */
    destination: text("destination").notNull(),
    /** 'pending' | 'approved' | 'rejected' | 'paid' */
    status: text("status").notNull().default("pending"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    processedAt: timestamp("processed_at", { withTimezone: true }),
  },
  (t) => [index("withdrawals_creator_idx").on(t.creatorId, t.createdAt)],
);

/* ------------------------------------------------------------------ */
/* App releases (in-app updater)                                       */
/* ------------------------------------------------------------------ */

/**
 * Published APK releases for the in-app updater. One row per published
 * version; the latest row per app_type is what clients are offered.
 * The APK binary lives in apk_data (bytea) so the backend can serve it
 * directly without depending on Drive sharing permissions.
 */
export const appReleases = pgTable(
  "app_releases",
  {
    id: text("id").primaryKey(), // uuid
    /** 'user' | 'creator' */
    appType: text("app_type").notNull(),
    versionCode: integer("version_code").notNull(),
    versionName: text("version_name").notNull(),
    apkData: bytea("apk_data").notNull(),
    apkSizeBytes: integer("apk_size_bytes").notNull(),
    /** MD5 hex of the APK — client verifies after download. */
    apkMd5: text("apk_md5").notNull(),
    changelog: text("changelog"),
    /** When true the client should block until the user updates. */
    mandatory: boolean("mandatory").notNull().default(false),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [index("app_releases_type_idx").on(t.appType, t.versionCode)],
);

export type AppRelease = typeof appReleases.$inferSelect;
