/**
 * MinuteMate API — OTP authentication + JWT session management.
 *
 * Flow:
 *   1. Client POSTs { phone } to /api/auth/send-otp.
 *      The phone is normalized to a 10-digit Indian mobile; anything else is
 *      rejected with 400. A 6-digit OTP is generated, SHA-256 hashed, and
 *      stored with a 5-minute TTL. Only the hash is stored — never the OTP.
 *      In production this is where the SMS provider call goes; in dev the
 *      OTP is logged to the console.
 *   2. Client POSTs { phone, otp } to /api/auth/verify-otp.
 *      On success the user row is created (first login) or fetched, and an
 *      access token (15 min) + refresh token (30 days, tracked jti) are
 *      issued.
 *   3. Authenticated routes use `Authorization: Bearer <access-token>`.
 *
 * Secrets: JWT_SECRET is REQUIRED in production — the server refuses to boot
 * without it. In non-production a loud warning is printed and a dev-only
 * fallback is used.
 */

import { createHash, randomInt, randomUUID } from "crypto";
import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { and, eq, gt } from "drizzle-orm";
import { db } from "./db.js";
import { otps, users, wallets, refreshTokens } from "./schema.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

function resolveJwtSecret(): string {
  const secret = process.env.JWT_SECRET;
  if (secret && secret.trim().length > 0) return secret;
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "FATAL: JWT_SECRET is not set. Set JWT_SECRET to a long random value " +
        "(e.g. `openssl rand -base64 64`) before starting in production.",
    );
  }
  console.warn("[auth] JWT_SECRET is not set — using an INSECURE dev-only fallback. Never deploy like this.");
  return "dev-only-insecure-secret-change-me";
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
  const otp = String(randomInt(100000, 1000000)); // 6 digits, no leading zero
  const expiresAt = new Date(Date.now() + OTP_TTL_MS);

  await db
    .insert(otps)
    .values({ phone, otpHash: sha256Hex(otp), expiresAt, attempts: 0 })
    .onConflictDoUpdate({
      target: otps.phone,
      set: { otpHash: sha256Hex(otp), expiresAt, attempts: 0, createdAt: new Date() },
    });

  return { otp, expiresAt };
}

/** Result of an OTP verification attempt. */
export type VerifyOtpResult =
  | { ok: true; userId: string; isNewUser: boolean }
  | { ok: false; error: string; status: number };

export async function verifyOtp(phone: string, otp: string): Promise<VerifyOtpResult> {
  if (!/^\d{6}$/.test(otp)) {
    return { ok: false, error: "Enter the 6-digit OTP", status: 400 };
  }

  // ---------------------------------------------------------------------------
  // TEMPORARY TEST ONLY — master OTP "123456" bypasses SMS verification.
  // Lets testers log into ANY phone number in both the user and creator apps
  // without a real SMS. !!! REMOVE BEFORE PRODUCTION LAUNCH !!!
  // Anyone who knows this code can access any account.
  // ---------------------------------------------------------------------------
  if (otp === "123456") {
    const existing = await db.select().from(users).where(eq(users.phone, phone)).limit(1);
    if (existing[0]) {
      return { ok: true, userId: existing[0].id, isNewUser: false };
    }
    const userId = randomUUID();
    await db.insert(users).values({ id: userId, phone });
    await db.insert(wallets).values({ userId, balancePaise: 0 });
    return { ok: true, userId, isNewUser: true };
  }

  const rows = await db.select().from(otps).where(eq(otps.phone, phone)).limit(1);
  const challenge = rows[0];
  if (!challenge) {
    return { ok: false, error: "No OTP was requested for this number. Please request a new one.", status: 400 };
  }
  if (challenge.expiresAt.getTime() < Date.now()) {
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
      .set({ attempts: Number(challenge.attempts) + 1 })
      .where(eq(otps.phone, phone));
    return { ok: false, error: "Incorrect OTP. Please try again.", status: 400 };
  }

  // OTP correct — consume it (single use) and resolve the user.
  await db.delete(otps).where(eq(otps.phone, phone));

  const existing = await db.select().from(users).where(eq(users.phone, phone)).limit(1);
  if (existing[0]) {
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
    .select()
    .from(refreshTokens)
    .where(and(eq(refreshTokens.jti, payload.jti), gt(refreshTokens.expiresAt, new Date())))
    .limit(1);
  if (!rows[0]) return null; // revoked or expired

  await revokeRefreshToken(payload.jti);
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
export function authenticateToken(req: Request, res: Response, next: NextFunction): void {
  const header = req.headers.authorization;
  const token = header?.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) {
    res.status(401).json({ error: "Authentication required. Please log in." });
    return;
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET) as AccessTokenPayload;
    if (payload.typ !== "access" || !payload.userId) {
      res.status(401).json({ error: "Invalid token. Please log in again." });
      return;
    }
    (req as AuthenticatedRequest).userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: "Session expired. Please log in again." });
  }
}
