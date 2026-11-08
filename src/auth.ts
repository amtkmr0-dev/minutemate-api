/**
 * MinuteMate API — OTP authentication + JWT session management.
 *
 * Flow:
 *   1. Client POSTs { phone } to /api/auth/send-otp.
 *      The phone is normalized to a 10-digit Indian mobile; anything else is
 *      rejected with 400. A 6-digit OTP is generated, SHA-256 hashed, and
 *      stored with a 5-minute TTL. Only the hash is stored — never the OTP.
 *      Sending requires an explicitly configured SMS provider; unconfigured
 *      delivery fails closed. The OTP is never returned or logged by routes.
 *   2. Client POSTs { phone, otp } to /api/auth/verify-otp.
 *      On success the user row is created (first login) or fetched, and an
 *      access token (15 min) + refresh token (30 days, tracked jti) are
 *      issued.
 *   3. Authenticated routes use `Authorization: Bearer <access-token>`.
 *
 * Secrets: JWT_SECRET is required in every environment. There is no shared
 * development signing key or test-authentication bypass.
 */

import { createHash, randomInt, randomUUID } from "crypto";
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { and, eq, gt, lt, sql } from "drizzle-orm";
import { db } from "./db.js";
import { otps, users, wallets, refreshTokens } from "./schema.js";
import { getSmsProvider, SmsError } from "./sms.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function resolveJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (secret && secret.trim().length > 0) return secret;
  throw new Error(
    "FATAL: JWT_SECRET is not set. Configure a long random signing secret before starting the server.",
  );
}

const JWT_SECRET = resolveJwtSecret();
const ACCESS_TOKEN_TTL = "15m";
const REFRESH_TOKEN_TTL_DAYS = 30;
const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Phone normalization (Indian mobiles)
// ---------------------------------------------------------------------------

/**
 * Normalize an Indian mobile number to 10 digits.
 * Accepts "+91 98765 43210", "919876543210", "09876543210", "98765 43210".
 * Returns null for anything that is not a valid 10-digit Indian mobile
 * (must start with 6, 7, 8 or 9).
 */
export function normalizeIndianMobile(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let digits = input.replace(/\D/g, "");
  // Strip country code / trunk prefix.
  if (digits.length === 12 && digits.startsWith("91")) digits = digits.slice(2);
  else if (digits.length === 11 && digits.startsWith("0")) digits = digits.slice(1);
  if (!/^[6-9]\d{9}$/.test(digits)) return null;
  return digits;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

// ---------------------------------------------------------------------------
// OTP issue / verify
// ---------------------------------------------------------------------------

/**
 * Generate an OTP challenge for a phone number. Returns the plain OTP so the
 * caller can send it via SMS; only the hash is persisted.
 */
export async function issueOtp(phone: string): Promise<{ otp: string; expiresAt: Date }> {
  // BUG 13 fix (2026-09-30): enforce a resend cooldown. The old code allowed
  // unlimited rapid resends, which resets the OTP each time and enables abuse.
  const COOLDOWN_MS = 30 * 1000; // 30 seconds between OTP sends
  const existing = await db.select().from(otps).where(eq(otps.phone, phone)).limit(1);
  if (existing[0]) {
    const sentAt = existing[0].createdAt.getTime();
    const elapsed = Date.now() - sentAt;
    if (elapsed < COOLDOWN_MS) {
      const waitSec = Math.ceil((COOLDOWN_MS - elapsed) / 1000);
      throw new Error(`Please wait ${waitSec} seconds before requesting a new OTP.`);
    }
  }

  const otp = String(randomInt(100000, 1000000)); // 6 digits, no leading zero
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  const issued = await db
    .insert(otps)
    .values({ phone, otpHash: sha256Hex(otp), expiresAt, attempts: 0 })
    .onConflictDoUpdate({
      target: otps.phone,
      set: { otpHash: sha256Hex(otp), expiresAt, attempts: 0, createdAt: new Date() },
      setWhere: lt(otps.createdAt, new Date(Date.now() - COOLDOWN_MS)),
    }).returning({ phone: otps.phone });
  if (!issued[0]) throw new Error("Please wait 30 seconds before requesting a new OTP.");

  return { otp, expiresAt };
}

/** Create a challenge only when a provider exists, then await its acceptance. */
export async function sendOtp(phone: string): Promise<void> {
  const provider = getSmsProvider();
  if (!provider) throw new SmsError("SMS_NOT_CONFIGURED", false);
  const { otp, expiresAt } = await issueOtp(phone);
  try {
    await provider.sendOtp(phone, otp);
  } catch {
    // Do not remove a newer challenge if a slow provider request fails.
    try {
      await db.delete(otps).where(and(
        eq(otps.phone, phone), eq(otps.otpHash, sha256Hex(otp)), eq(otps.expiresAt, expiresAt),
      ));
    } finally {
      // Provider errors may contain phone numbers or credentials; never expose them.
      throw new SmsError("SMS_DELIVERY_FAILED", true);
    }
  }
}

/** Result of an OTP verification attempt. */
export type VerifyOtpResult =
  | { ok: true; userId: string; isNewUser: boolean }
  | { ok: false; error: string; status: number; code?: string };

export async function verifyOtp(phone: string, otp: string): Promise<VerifyOtpResult> {
  if (!/^\d{6}$/.test(otp)) {
    return { ok: false, error: "Enter the 6-digit OTP", status: 400 };
  }

  const rows = await db.select().from(otps).where(eq(otps.phone, phone)).limit(1);
  const challenge = rows[0];
  if (!challenge) {
    return { ok: false, error: "No OTP was requested for this number. Please request a new one.", status: 400 };
  }
  if (challenge.expiresAt.getTime() <= Date.now()) {
    await db.delete(otps).where(eq(otps.phone, phone));
    return { ok: false, error: "OTP expired. Please request a new one.", status: 400 };
  }
  if (Number(challenge.attempts) >= OTP_MAX_ATTEMPTS) {
    await db.delete(otps).where(eq(otps.phone, phone));
    return { ok: false, error: "Too many wrong attempts. Please request a new OTP.", status: 429 };
  }

  const matches = sha256Hex(otp) === challenge.otpHash;
  if (!matches) {
    await db
      .update(otps)
      .set({ attempts: sql`${otps.attempts} + 1` })
      .where(and(
        eq(otps.phone, phone),
        eq(otps.otpHash, challenge.otpHash),
        gt(otps.expiresAt, new Date(Date.now())),
        lt(otps.attempts, OTP_MAX_ATTEMPTS),
      ));
    return { ok: false, error: "Incorrect OTP. Please try again.", status: 400 };
  }

  // Claim the exact live challenge atomically. A concurrent verifier must not
  // issue another session after this request consumes it.
  const consumed = await db.delete(otps).where(and(
    eq(otps.phone, phone),
    eq(otps.otpHash, challenge.otpHash),
    eq(otps.expiresAt, challenge.expiresAt),
    gt(otps.expiresAt, new Date(Date.now())),
    lt(otps.attempts, OTP_MAX_ATTEMPTS),
  )).returning({ phone: otps.phone });
  if (!consumed[0]) {
    return { ok: false, error: "OTP is no longer valid. Please request a new one.", status: 400 };
  }

  const existing = await db.select().from(users).where(eq(users.phone, phone)).limit(1);
  if (existing[0]) {
    if (existing[0].status !== "active") {
      return { ok: false, error: "This account is not active.", status: 403, code: "ACCOUNT_DISABLED" };
    }
    return { ok: true, userId: existing[0].id, isNewUser: false };
  }

  const userId = randomUUID();
  await db.insert(users).values({ id: userId, phone });
  await db.insert(wallets).values({ userId, balancePaise: 0 });
  return { ok: true, userId, isNewUser: true };
}

// ---------------------------------------------------------------------------
// JWT session tokens
// ---------------------------------------------------------------------------

export interface AccessTokenPayload {
  userId: string;
  typ: "access";
}

export interface RefreshTokenPayload {
  userId: string;
  typ: "refresh";
  jti: string;
}

export function signAccessToken(userId: string): string {
  return jwt.sign({ userId, typ: "access" } satisfies AccessTokenPayload, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
}

/**
 * Issue a refresh token and record its jti so logout/rotation can revoke it.
 */
export async function signRefreshToken(userId: string): Promise<string> {
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);
  await db.insert(refreshTokens).values({ jti, userId, expiresAt });
  return jwt.sign({ userId, typ: "refresh", jti } satisfies RefreshTokenPayload, JWT_SECRET, {
    expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
  });
}

/** Revoke a refresh token by jti (logout). */
export async function revokeRefreshToken(jti: string): Promise<void> {
  await db.delete(refreshTokens).where(eq(refreshTokens.jti, jti));
}

/**
 * Rotate a refresh token: the presented token must be a live, unexpired,
 * non-revoked refresh token; it is revoked and a fresh pair is issued.
 */
export async function rotateRefreshToken(
  token: string,
): Promise<{ accessToken: string; refreshToken: string; userId: string } | null> {
  let payload: RefreshTokenPayload;
  try {
    payload = jwt.verify(token, JWT_SECRET) as RefreshTokenPayload;
  } catch {
    return null;
  }
  if (payload.typ !== "refresh" || !payload.jti) return null;

  const rows = await db
    .delete(refreshTokens)
    .where(and(eq(refreshTokens.jti, payload.jti), gt(refreshTokens.expiresAt, new Date())))
    .returning();
  if (!rows[0]) return null; // revoked, expired or another rotation won

  const account = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
  if (!account[0] || account[0].status !== "active") return null;

  const accessToken = signAccessToken(payload.userId);
  const refreshToken = await signRefreshToken(payload.userId);
  return { accessToken, refreshToken, userId: payload.userId };
}

// ---------------------------------------------------------------------------
// Express middleware
// ---------------------------------------------------------------------------

export interface AuthenticatedRequest extends Request {
  userId: string;
}

/**
 * Require a valid Bearer access token. Attaches req.userId.
 * Rejects the wrong token type (refresh tokens are not accepted here).
 */
export async function authenticateToken(req: Request, res: Response, next: NextFunction): Promise<void> {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    res.status(401).json({ error: "Authentication required. Please log in." });
    return;
  }
  let payload: AccessTokenPayload;
  try {
    payload = jwt.verify(token, JWT_SECRET) as AccessTokenPayload;
    if (payload.typ !== "access" || !payload.userId) {
      res.status(401).json({ error: "Invalid token. Please log in again." });
      return;
    }
  } catch {
    res.status(401).json({ error: "Session expired. Please log in again." });
    return;
  }
  try {
    const [account] = await db.select().from(users).where(eq(users.id, payload.userId)).limit(1);
    if (!account) {
      res.status(401).json({ error: "Account not found. Please log in again." });
      return;
    }
    if (account.status !== "active") {
      res.status(403).json({ error: "This account is not active.", code: "ACCOUNT_DISABLED" });
      return;
    }
    (req as AuthenticatedRequest).userId = payload.userId;
    next();
  } catch {
    res.status(503).json({ error: "Authentication is temporarily unavailable.", code: "AUTH_UNAVAILABLE" });
  }
}
