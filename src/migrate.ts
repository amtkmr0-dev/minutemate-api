/**
 * MinuteMate API — idempotent startup migration.
 *
 * Applies DDL for all tables (CREATE TABLE IF NOT EXISTS + ADD COLUMN IF NOT
 * EXISTS) so a fresh Neon database is fully provisioned on boot, and existing
 * databases are upgraded without data loss. Safe to run on every startup.
 *
 * The DDL mirrors src/schema.ts (Drizzle) exactly so `drizzle-kit push`
 * remains a no-op for these objects.
 */

import { sql } from "./db.js";

const DDL: string[] = [
  // users: role + status (added after initial launch)
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS role text NOT NULL DEFAULT 'user'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url text`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS member_id text UNIQUE`,
  `ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name text`,

  // creator profiles
  `CREATE TABLE IF NOT EXISTS creator_profiles (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    display_name text NOT NULL,
    bio text,
    languages text NOT NULL DEFAULT 'Hindi,English',
    price_per_min_paise bigint NOT NULL DEFAULT 2000,
    avatar_url text,
    media_urls text NOT NULL DEFAULT '[]',
    intro_video_url text,
    allowed_call_types text NOT NULL DEFAULT 'both',
    verification_status text NOT NULL DEFAULT 'pending',
    kyc_status text NOT NULL DEFAULT 'pending',
    is_online boolean NOT NULL DEFAULT false,
    random_match_enabled boolean NOT NULL DEFAULT true,
    rating integer NOT NULL DEFAULT 0,
    rating_count integer NOT NULL DEFAULT 0,
    total_calls integer NOT NULL DEFAULT 0,
    total_minutes integer NOT NULL DEFAULT 0,
    agency_id text,
    talks_about text NOT NULL DEFAULT '[]',
    hobbies text NOT NULL DEFAULT '[]',
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    updated_at timestamp with time zone NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS creator_profiles_online_idx ON creator_profiles (is_online, verification_status)`,
  `CREATE INDEX IF NOT EXISTS creator_profiles_agency_idx ON creator_profiles (agency_id)`,

  // creator earnings wallet
  `CREATE TABLE IF NOT EXISTS creator_wallets (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    balance_paise bigint NOT NULL DEFAULT 0,
    lifetime_paise bigint NOT NULL DEFAULT 0,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
  )`,

  // creator bank / UPI payout details
  `CREATE TABLE IF NOT EXISTS creator_bank_details (
    user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    account_holder text,
    account_number text,
    ifsc text,
    upi_id text,
    updated_at timestamp with time zone NOT NULL DEFAULT now()
  )`,

  // KYC submissions
  `CREATE TABLE IF NOT EXISTS kyc_submissions (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    doc_type text NOT NULL,
    doc_url text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    reviewer_note text,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    reviewed_at timestamp with time zone
  )`,
  `CREATE INDEX IF NOT EXISTS kyc_submissions_user_idx ON kyc_submissions (user_id)`,

  // blocks
  `CREATE TABLE IF NOT EXISTS blocks (
    blocker_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    PRIMARY KEY (blocker_id, blocked_id)
  )`,
  `CREATE INDEX IF NOT EXISTS blocks_blocker_idx ON blocks (blocker_id)`,

  // chat threads
  `CREATE TABLE IF NOT EXISTS chat_threads (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    creator_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    last_message_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS chat_threads_user_idx ON chat_threads (user_id, last_message_at)`,
  `CREATE INDEX IF NOT EXISTS chat_threads_creator_idx ON chat_threads (creator_id, last_message_at)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS chat_threads_pair_uidx ON chat_threads (user_id, creator_id)`,

  // chat messages
  `CREATE TABLE IF NOT EXISTS chat_messages (
    id text PRIMARY KEY,
    thread_id text NOT NULL REFERENCES chat_threads(id) ON DELETE CASCADE,
    sender_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    sender_role text NOT NULL,
    body text NOT NULL,
    kind text NOT NULL DEFAULT 'text',
    gift_id text,
    created_at timestamp with time zone NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS chat_messages_thread_idx ON chat_messages (thread_id, created_at)`,

  // call sessions
  `CREATE TABLE IF NOT EXISTS call_sessions (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    creator_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    room_id text NOT NULL,
    call_type text NOT NULL DEFAULT 'video',
    status text NOT NULL DEFAULT 'ringing',
    rate_paise_per_min bigint NOT NULL DEFAULT 0,
    duration_sec integer NOT NULL DEFAULT 0,
    cost_paise bigint NOT NULL DEFAULT 0,
    last_heartbeat_at timestamp with time zone,
    started_at timestamp with time zone,
    ended_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    user_media_at timestamp with time zone,
    creator_media_at timestamp with time zone,
    media_confirmed_at timestamp with time zone,
    billable_heartbeat_at timestamp with time zone
  )`,
  `CREATE INDEX IF NOT EXISTS call_sessions_user_idx ON call_sessions (user_id, created_at)`,
  `CREATE INDEX IF NOT EXISTS call_sessions_creator_idx ON call_sessions (creator_id, created_at)`,
  `CREATE INDEX IF NOT EXISTS call_sessions_status_idx ON call_sessions (status, created_at)`,
  // billing justice (2026-10-02): two-sided media confirmation columns
  `ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS user_media_at timestamp with time zone`,
  `ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS creator_media_at timestamp with time zone`,
  `ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS media_confirmed_at timestamp with time zone`,
  `ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS billable_heartbeat_at timestamp with time zone`,

  // gift catalog
  `CREATE TABLE IF NOT EXISTS gifts (
    id text PRIMARY KEY,
    name text NOT NULL,
    emoji text NOT NULL,
    price_paise bigint NOT NULL,
    sort_order integer NOT NULL DEFAULT 0
  )`,

  // gift ledger
  `CREATE TABLE IF NOT EXISTS gift_transactions (
    id text PRIMARY KEY,
    from_user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    to_creator_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    gift_id text NOT NULL REFERENCES gifts(id),
    price_paise bigint NOT NULL,
    call_session_id text,
    created_at timestamp with time zone NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS gift_transactions_creator_idx ON gift_transactions (to_creator_id, created_at)`,

  // withdrawals
  `CREATE TABLE IF NOT EXISTS withdrawals (
    id text PRIMARY KEY,
    creator_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount_paise bigint NOT NULL,
    destination text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    created_at timestamp with time zone NOT NULL DEFAULT now(),
    processed_at timestamp with time zone
  )`,
  `CREATE INDEX IF NOT EXISTS withdrawals_creator_idx ON withdrawals (creator_id, created_at)`,

  // app_releases: in-app updater (2026-09-29)
  `CREATE TABLE IF NOT EXISTS app_releases (
    id text PRIMARY KEY,
    app_type text NOT NULL,
    version_code integer NOT NULL,
    version_name text NOT NULL,
    apk_data bytea,
    apk_url text,
    apk_size_bytes integer NOT NULL,
    apk_md5 text NOT NULL,
    changelog text,
    mandatory boolean NOT NULL DEFAULT false,
    created_at timestamp with time zone NOT NULL DEFAULT now()
  )`,
  `CREATE INDEX IF NOT EXISTS app_releases_type_idx ON app_releases (app_type, version_code)`,
  `ALTER TABLE app_releases ALTER COLUMN apk_data DROP NOT NULL`,
  `ALTER TABLE app_releases ADD COLUMN IF NOT EXISTS apk_url text`,
];

const SEED_GIFTS: Array<[string, string, string, number, number]> = [
  ["rose", "Rose", "🌹", 1000, 1], // ₹10
  ["coffee", "Coffee", "☕", 2000, 2], // ₹20
  ["heart", "Heart", "❤️", 5000, 3], // ₹50
  ["crown", "Crown", "👑", 10000, 4], // ₹100
  ["diamond", "Diamond", "💎", 20000, 5], // ₹200
  ["rocket", "Rocket", "🚀", 50000, 6], // ₹500
  ["trophy", "Trophy", "🏆", 100000, 7], // ₹1000
  ["kohinoor", "Kohinoor", "💠", 200000, 8], // ₹2000
];

/** Run all DDL + seed the gift catalog. Idempotent. */
export async function runStartupMigration(): Promise<void> {
  for (const stmt of DDL) {
    await sql(stmt);
  }
  for (const [id, name, emoji, pricePaise, sortOrder] of SEED_GIFTS) {
    await sql(
      `INSERT INTO gifts (id, name, emoji, price_paise, sort_order)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, emoji = EXCLUDED.emoji,
         price_paise = EXCLUDED.price_paise, sort_order = EXCLUDED.sort_order`,
      [id, name, emoji, pricePaise, sortOrder],
    );
  }
}
