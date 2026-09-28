/**
 * MinuteMate API — creators, chat, calls, blocks, gifts, uploads.
 *
 * Persistent Neon-backed implementations for everything the user and creator
 * apps need. Money is stored in PAISE as integers; responses expose both
 * rupees and paise (same convention as wallet.ts).
 *
 * Trial-mode decisions (revisit before production scale):
 * - Creator onboarding auto-approves verificationStatus='approved'. The admin
 *   approval queue arrives with the dashboard phase.
 * - Uploads are validated data URLs stored inline (no object storage yet).
 *   Migrate to S3/R2 before real KYC volume.
 * - Call earnings go 100% to the creator (no platform commission deducted).
 */

import type { Express, Request, Response, NextFunction } from "express";
import { and, desc, eq, ilike, ne, or } from "drizzle-orm";
import { randomUUID } from "node:crypto";
import { db, sql } from "./db.js";
import {
  authenticateToken,
  issueOtp,
  normalizeIndianMobile,
  signAccessToken,
  signRefreshToken,
  verifyOtp,
  type AuthenticatedRequest,
} from "./auth.js";
import { getUserById } from "./payments.js";
import { getWalletSummary } from "./wallet.js";
import {
  blocks,
  callSessions,
  chatMessages,
  chatThreads,
  creatorBankDetails,
  creatorProfiles,
  creatorWallets,
  gifts,
  giftTransactions,
  kycSubmissions,
  users,
  wallets,
  withdrawals,
  transactions,
} from "./schema.js";

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function httpError(res: Response, err: unknown, fallback: string): void {
  const status = (err as { statusCode?: number })?.statusCode ?? 500;
  const message = err instanceof Error ? err.message : fallback;
  res.status(status).json({ error: message });
}

function safeJsonArray(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch {
    return [];
  }
}

const authed = (req: Request): string => (req as AuthenticatedRequest).userId;

/** Load the requester and enforce one of the given roles. */
function requireRole(...roles: string[]) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const user = await getUserById(authed(req));
      if (!user) {
        res.status(401).json({ error: "Account not found. Please log in again." });
        return;
      }
      if (user.status === "banned") {
        res.status(403).json({ error: "This account has been suspended." });
        return;
      }
      if (!roles.includes(user.role)) {
        res.status(403).json({ error: "Not authorized for this action." });
        return;
      }
      next();
    } catch (err) {
      httpError(res, err, "Authorization check failed.");
    }
  };
}

type UserRow = NonNullable<Awaited<ReturnType<typeof getUserById>>>;
type ProfileRow = typeof creatorProfiles.$inferSelect;

function parseLanguages(raw: string | null | undefined): string[] {
  if (!raw) return [];
  const t = raw.trim();
  if (t.startsWith("[")) return safeJsonArray(t);
  return t.split(",").map((s) => s.trim()).filter(Boolean);
}

function creatorCard(user: UserRow, p: ProfileRow) {
  return {
    id: user.id,
    name: p.displayName,
    avatarUrl: p.avatarUrl,
    languages: parseLanguages(p.languages),
    pricePerMin: Number(p.pricePerMinPaise) / 100,
    pricePerMinPaise: Number(p.pricePerMinPaise),
    rating: Number(p.rating) / 10,
    ratingCount: p.ratingCount,
    isOnline: p.isOnline,
    allowedCallTypes: p.allowedCallTypes,
    totalCalls: p.totalCalls,
  };
}

function creatorFull(user: UserRow, p: ProfileRow) {
  return {
    ...creatorCard(user, p),
    bio: p.bio,
    mediaUrls: safeJsonArray(p.mediaUrls),
    introVideoUrl: p.introVideoUrl,
    talksAbout: safeJsonArray(p.talksAbout),
    hobbies: safeJsonArray(p.hobbies),
    totalMinutes: p.totalMinutes,
    verificationStatus: p.verificationStatus,
  };
}

/** Ids the requester has blocked, plus ids that blocked the requester. */
async function blockedIdsBothWays(userId: string): Promise<Set<string>> {
  const out = await db.select().from(blocks).where(or(eq(blocks.blockerId, userId), eq(blocks.blockedId, userId)));
  const s = new Set<string>();
  for (const b of out) {
    s.add(b.blockerId === userId ? b.blockedId : b.blockerId);
  }
  return s;
}

/** Atomic wallet debit. Returns the new balance, or null on insufficient funds. */
async function debitUserWallet(userId: string, amountPaise: number): Promise<number | null> {
  const rows = (await sql(
    `UPDATE wallets SET balance_paise = balance_paise - $1, updated_at = now()
     WHERE user_id = $2 AND balance_paise >= $1 RETURNING balance_paise`,
    [amountPaise, userId],
  )) as Array<{ balance_paise: string }>;
  if (rows.length === 0) return null;
  return Number(rows[0].balance_paise);
}

/** Credit creator earnings (100% of amount in trial mode). */
async function creditCreatorEarnings(creatorId: string, amountPaise: number): Promise<void> {
  await sql(
    `INSERT INTO creator_wallets (user_id, balance_paise, lifetime_paise)
     VALUES ($1, $2, $2)
     ON CONFLICT (user_id) DO UPDATE SET
       balance_paise = creator_wallets.balance_paise + EXCLUDED.balance_paise,
       lifetime_paise = creator_wallets.lifetime_paise + EXCLUDED.lifetime_paise,
       updated_at = now()`,
    [creatorId, amountPaise],
  );
}

async function recordWalletTransaction(
  userId: string,
  type: string,
  amountPaise: number,
  description: string,
): Promise<void> {
  const bal = await getWalletSummary(userId);
  await db.insert(transactions).values({
    id: randomUUID(),
    userId,
    type,
    amountPaise,
    bonusPaise: 0,
    balanceAfterPaise: bal.balancePaise,
    description,
  });
}

/** Mark stale ringing sessions as missed. Returns true if the given session was swept. */
async function sweepStaleRinging(sessionId?: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - 90_000);
  if (sessionId) {
    const rows = await db.select().from(callSessions).where(eq(callSessions.id, sessionId)).limit(1);
    const s = rows[0];
    if (s && s.status === "ringing" && s.createdAt.getTime() < cutoff.getTime()) {
      await db.update(callSessions).set({ status: "missed", endedAt: new Date() }).where(eq(callSessions.id, sessionId));
      return true;
    }
    return false;
  }
  await sql(`UPDATE call_sessions SET status = 'missed', ended_at = now()
             WHERE status = 'ringing' AND created_at < $1`, [cutoff.toISOString()]);
  return false;
}

function sessionView(s: typeof callSessions.$inferSelect) {
  return {
    sessionId: s.id,
    id: s.id,
    userId: s.userId,
    creatorId: s.creatorId,
    roomId: s.roomId,
    callType: s.callType,
    status: s.status,
    pricePerMinute: Number(s.ratePaisePerMin) / 100,
    ratePaisePerMin: Number(s.ratePaisePerMin),
    durationSec: s.durationSec,
    cost: Number(s.costPaise) / 100,
    costPaise: Number(s.costPaise),
    startedAt: s.startedAt?.toISOString() ?? null,
    endedAt: s.endedAt?.toISOString() ?? null,
    createdAt: s.createdAt.toISOString(),
  };
}

/** Validate a data URL upload. Returns the byte size or an error string. */
function validateDataUrl(dataUrl: unknown, opts: { imagesOnly: boolean; maxBytes: number }): number | string {
  if (typeof dataUrl !== "string") return "Upload data is required.";
  const m = dataUrl.match(/^data:([a-z]+\/[a-z0-9.+-]+);base64,([A-Za-z0-9+/=]+)$/i);
  if (!m) return "Invalid file format. Please choose a valid file.";
  const mime = m[1].toLowerCase();
  const okImage = ["image/jpeg", "image/png", "image/webp"].includes(mime);
  const okVideo = ["video/mp4", "video/webm"].includes(mime);
  if (opts.imagesOnly ? !okImage : !(okImage || okVideo)) {
    return opts.imagesOnly ? "Please upload a JPG, PNG or WebP image." : "Please upload a JPG, PNG, WebP, MP4 or WebM file.";
  }
  const bytes = Math.floor(m[2].length * 3 / 4);
  if (bytes > opts.maxBytes) {
    return `File is too large (max ${Math.round(opts.maxBytes / 1024 / 1024)} MB).`;
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// routes
// ---------------------------------------------------------------------------

export function registerCreatorRoutes(app: Express): void {
  // ---------------------------------------------------------- creator auth
  // Same OTP flow as users; the creator app just lands the account in the
  // creator role so the creator dashboard unlocks after onboarding.

  app.post("/api/auth/creator/send-otp", async (req: Request, res: Response) => {
    const phone = normalizeIndianMobile((req.body as { phone?: unknown } | undefined)?.phone);
    if (!phone) {
      res.status(400).json({ error: "Enter a valid 10-digit mobile number." });
      return;
    }
    try {
      await issueOtp(phone);
      res.json({ success: true, message: "OTP sent successfully" });
    } catch (err) {
      httpError(res, err, "Could not send OTP. Please try again.");
    }
  });

  app.post("/api/auth/creator/verify-otp", async (req: Request, res: Response) => {
    const body = (req.body as { phone?: unknown; otp?: unknown } | undefined) ?? {};
    const phone = normalizeIndianMobile(body.phone);
    if (!phone) {
      res.status(400).json({ error: "Enter a valid 10-digit mobile number." });
      return;
    }
    try {
      const result = await verifyOtp(phone, String(body.otp ?? ""));
      if (!result.ok) {
        res.status(result.status).json({ error: result.error });
        return;
      }
      // Creator app login: ensure the account carries the creator role
      // (a phone can be both a user and a creator — same account, two apps).
      const existing = await getUserById(result.userId);
      if (existing && existing.role === "user") {
        await db.update(users).set({ role: "creator", updatedAt: new Date() }).where(eq(users.id, result.userId));
      }
      const accessToken = signAccessToken(result.userId);
      const refreshToken = await signRefreshToken(result.userId);
      const user = await getUserById(result.userId);
      res.json({
        success: true,
        isNewUser: result.isNewUser,
        accessToken,
        token: accessToken,
        refreshToken,
        user: user
          ? { id: user.id, phone: user.phone, name: user.name, email: user.email, role: user.role, avatarUrl: user.avatarUrl }
          : { id: result.userId, phone, role: "creator" },
      });
    } catch (err) {
      httpError(res, err, "Could not verify OTP. Please try again.");
    }
  });

  // ---------------------------------------------------------- user profile
  app.get("/api/user/me", authenticateToken, async (req: Request, res: Response) => {
    try {
      const user = await getUserById(authed(req));
      if (!user) {
        res.status(401).json({ error: "Please log in again." });
        return;
      }
      res.json({ user: { id: user.id, phone: user.phone, name: user.name, email: user.email, role: user.role, avatarUrl: user.avatarUrl } });
    } catch (err) {
      httpError(res, err, "Could not load profile.");
    }
  });

  app.put("/api/user/profile", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { name?: unknown; email?: unknown; avatarUrl?: unknown } | undefined) ?? {};
    const name = typeof body.name === "string" ? body.name.trim().slice(0, 60) : undefined;
    const email = typeof body.email === "string" ? body.email.trim().slice(0, 120) : undefined;
    const avatarUrl = typeof body.avatarUrl === "string" && body.avatarUrl.startsWith("data:image/") ? body.avatarUrl.slice(0, 500_000) : undefined;
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      res.status(400).json({ error: "Enter a valid email address." });
      return;
    }
    try {
      const patch: Record<string, unknown> = { updatedAt: new Date() };
      if (name !== undefined) patch.name = name || null;
      if (email !== undefined) patch.email = email || null;
      if (avatarUrl !== undefined) patch.avatarUrl = avatarUrl || null;
      await db.update(users).set(patch).where(eq(users.id, authed(req)));
      const user = await getUserById(authed(req));
      res.json({
        success: true,
        user: user ? { id: user.id, phone: user.phone, name: user.name, email: user.email, role: user.role, avatarUrl: user.avatarUrl } : null,
      });
    } catch (err) {
      httpError(res, err, "Could not save profile.");
    }
  });

  // ---------------------------------------------------------- creator directory (user-facing)
  app.get("/api/creators", authenticateToken, async (req: Request, res: Response) => {
    try {
      const me = authed(req);
      const q = typeof req.query.q === "string" ? req.query.q.trim().slice(0, 60) : "";
      const onlineOnly = req.query.onlineOnly === "1" || req.query.onlineOnly === "true";

      const conds = [eq(creatorProfiles.verificationStatus, "approved"), eq(users.status, "active"), ne(users.id, me)];
      if (q) conds.push(ilike(creatorProfiles.displayName, `%${q}%`));
      if (onlineOnly) conds.push(eq(creatorProfiles.isOnline, true));

      const rows = await db
        .select({ user: users, profile: creatorProfiles })
        .from(users)
        .innerJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .where(and(...conds))
        .orderBy(desc(creatorProfiles.isOnline), desc(creatorProfiles.rating))
        .limit(100);

      const blocked = await blockedIdsBothWays(me);
      const creators = rows
        .filter((r) => !blocked.has(r.user.id))
        .map((r) => creatorCard(r.user, r.profile));
      res.json({ creators });
    } catch (err) {
      httpError(res, err, "Could not load creators.");
    }
  });

  app.get("/api/creators/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      const me = authed(req);
      const rows = await db
        .select({ user: users, profile: creatorProfiles })
        .from(users)
        .innerJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .where(and(eq(users.id, req.params.id), eq(creatorProfiles.verificationStatus, "approved")))
        .limit(1);
      const row = rows[0];
      if (!row) {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      const blocked = await blockedIdsBothWays(me);
      if (blocked.has(row.user.id)) {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      res.json({ creator: creatorFull(row.user, row.profile) });
    } catch (err) {
      httpError(res, err, "Could not load creator.");
    }
  });

  // ---------------------------------------------------------- creator self-service
  app.post("/api/creator/apply", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const user = await getUserById(userId);
      if (!user) {
        res.status(401).json({ error: "Please log in again." });
        return;
      }
      if (user.role !== "creator" && user.role !== "agency") {
        await db.update(users).set({ role: "creator", updatedAt: new Date() }).where(eq(users.id, userId));
      }
      await db
        .insert(creatorProfiles)
        .values({ userId, displayName: user.name || `Creator ${user.phone.slice(-4)}` })
        .onConflictDoNothing();
      await db.insert(creatorWallets).values({ userId }).onConflictDoNothing();
      const profile = await db.select().from(creatorProfiles).where(eq(creatorProfiles.userId, userId)).limit(1);
      res.json({ success: true, profile: profile[0] ? creatorFull(user, profile[0]) : null });
    } catch (err) {
      httpError(res, err, "Could not start creator application.");
    }
  });

  /** One-shot onboarding: creates/updates the public profile. Trial mode: auto-approved. */
  app.post("/api/creator/onboarding", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as Record<string, unknown> | undefined) ?? {};
    const displayName = typeof body.displayName === "string" ? body.displayName.trim().slice(0, 40) : "";
    if (displayName.length < 2) {
      res.status(400).json({ error: "Please enter your display name." });
      return;
    }
    const priceRupees = Number(body.pricePerMin ?? body.price ?? 30);
    if (!Number.isFinite(priceRupees) || priceRupees < 10 || priceRupees > 500) {
      res.status(400).json({ error: "Price must be between ₹10 and ₹500 per minute." });
      return;
    }
    const langs = Array.isArray(body.languages) ? body.languages.filter((l): l is string => typeof l === "string").slice(0, 8) : ["Hindi", "English"];
    const callTypes = body.allowedCallTypes === "audio" || body.allowedCallTypes === "video" ? body.allowedCallTypes : "both";
    try {
      const userId = authed(req);
      const user = await getUserById(userId);
      if (!user) {
        res.status(401).json({ error: "Please log in again." });
        return;
      }
      if (user.role === "user") {
        await db.update(users).set({ role: "creator", updatedAt: new Date() }).where(eq(users.id, userId));
      }
      const values = {
        userId,
        displayName,
        bio: typeof body.bio === "string" ? body.bio.trim().slice(0, 500) : null,
        languages: langs.join(","),
        pricePerMinPaise: Math.round(priceRupees * 100),
        avatarUrl: typeof body.avatarUrl === "string" ? body.avatarUrl.slice(0, 50_000) : null,
        allowedCallTypes: callTypes,
        talksAbout: JSON.stringify(Array.isArray(body.talksAbout) ? body.talksAbout.filter((t): t is string => typeof t === "string").slice(0, 10) : []),
        hobbies: JSON.stringify(Array.isArray(body.hobbies) ? body.hobbies.filter((t): t is string => typeof t === "string").slice(0, 10) : []),
        verificationStatus: "approved", // trial mode — admin approval queue arrives with the dashboard
        updatedAt: new Date(),
      };
      await db.insert(creatorProfiles).values(values).onConflictDoUpdate({ target: creatorProfiles.userId, set: values });
      await db.insert(creatorWallets).values({ userId }).onConflictDoNothing();
      const updated = await getUserById(userId);
      const profile = await db.select().from(creatorProfiles).where(eq(creatorProfiles.userId, userId)).limit(1);
      res.json({ success: true, profile: profile[0] && updated ? creatorFull(updated, profile[0]) : null });
    } catch (err) {
      httpError(res, err, "Could not save your profile.");
    }
  });

  app.get("/api/creator/profile", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const user = await getUserById(userId);
      const profile = await db.select().from(creatorProfiles).where(eq(creatorProfiles.userId, userId)).limit(1);
      const walletRows = await db.select().from(creatorWallets).where(eq(creatorWallets.userId, userId)).limit(1);
      const kyc = await db.select().from(kycSubmissions).where(eq(kycSubmissions.userId, userId)).orderBy(desc(kycSubmissions.createdAt)).limit(10);
      res.json({
        profile: profile[0] && user ? creatorFull(user, profile[0]) : null,
        earnings: walletRows[0]
          ? { balance: Number(walletRows[0].balancePaise) / 100, balancePaise: Number(walletRows[0].balancePaise), lifetime: Number(walletRows[0].lifetimePaise) / 100 }
          : { balance: 0, balancePaise: 0, lifetime: 0 },
        kyc: kyc.map((k) => ({ id: k.id, docType: k.docType, status: k.status, createdAt: k.createdAt.toISOString() })),
      });
    } catch (err) {
      httpError(res, err, "Could not load creator profile.");
    }
  });

  app.put("/api/creator/profile", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const body = (req.body as Record<string, unknown> | undefined) ?? {};
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (typeof body.displayName === "string" && body.displayName.trim().length >= 2) patch.displayName = body.displayName.trim().slice(0, 40);
    if (typeof body.bio === "string") patch.bio = body.bio.trim().slice(0, 500) || null;
    if (Array.isArray(body.languages)) patch.languages = body.languages.filter((l): l is string => typeof l === "string").slice(0, 8).join(",");
    if (body.pricePerMin !== undefined || body.price !== undefined) {
      const pr = Number(body.pricePerMin ?? body.price);
      if (!Number.isFinite(pr) || pr < 10 || pr > 500) {
        res.status(400).json({ error: "Price must be between ₹10 and ₹500 per minute." });
        return;
      }
      patch.pricePerMinPaise = Math.round(pr * 100);
    }
    if (body.allowedCallTypes === "audio" || body.allowedCallTypes === "video" || body.allowedCallTypes === "both") patch.allowedCallTypes = body.allowedCallTypes;
    if (typeof body.avatarUrl === "string") patch.avatarUrl = body.avatarUrl.slice(0, 50_000) || null;
    if (typeof body.introVideoUrl === "string") patch.introVideoUrl = body.introVideoUrl.slice(0, 50_000) || null;
    if (Array.isArray(body.mediaUrls)) patch.mediaUrls = JSON.stringify(body.mediaUrls.filter((u): u is string => typeof u === "string").slice(0, 12));
    if (Array.isArray(body.talksAbout)) patch.talksAbout = JSON.stringify(body.talksAbout.filter((t): t is string => typeof t === "string").slice(0, 10));
    if (Array.isArray(body.hobbies)) patch.hobbies = JSON.stringify(body.hobbies.filter((t): t is string => typeof t === "string").slice(0, 10));
    if (typeof body.randomMatchEnabled === "boolean") patch.randomMatchEnabled = body.randomMatchEnabled;
    try {
      const userId = authed(req);
      await db.update(creatorProfiles).set(patch).where(eq(creatorProfiles.userId, userId));
      const user = await getUserById(userId);
      const profile = await db.select().from(creatorProfiles).where(eq(creatorProfiles.userId, userId)).limit(1);
      res.json({ success: true, profile: profile[0] && user ? creatorFull(user, profile[0]) : null });
    } catch (err) {
      httpError(res, err, "Could not update profile.");
    }
  });

  app.post("/api/creator/presence", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const online = (req.body as { online?: unknown } | undefined)?.online === true;
    try {
      await db.update(creatorProfiles).set({ isOnline: online, updatedAt: new Date() }).where(eq(creatorProfiles.userId, authed(req)));
      res.json({ success: true, isOnline: online });
    } catch (err) {
      httpError(res, err, "Could not update presence.");
    }
  });

  /** Creator polls this for incoming calls (status=ringing, fresh). */
  app.get("/api/creator/incoming-calls", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      await sweepStaleRinging();
      const rows = await db
        .select({ session: callSessions, user: users })
        .from(callSessions)
        .innerJoin(users, eq(users.id, callSessions.userId))
        .where(and(eq(callSessions.creatorId, authed(req)), eq(callSessions.status, "ringing")))
        .orderBy(desc(callSessions.createdAt))
        .limit(10);
      res.json({
        calls: rows.map((r) => ({
          ...sessionView(r.session),
          caller: { id: r.user.id, name: r.user.name, phone: r.user.phone.slice(0, 2) + "••••" + r.user.phone.slice(-2) },
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not check for incoming calls.");
    }
  });

  app.post("/api/creator/kyc", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const body = (req.body as { docType?: unknown; docUrl?: unknown } | undefined) ?? {};
    const docType = typeof body.docType === "string" ? body.docType : "";
    if (!["aadhaar", "pan", "selfie", "video"].includes(docType)) {
      res.status(400).json({ error: "Invalid document type." });
      return;
    }
    if (typeof body.docUrl !== "string" || body.docUrl.length < 100) {
      res.status(400).json({ error: "Document upload is required." });
      return;
    }
    try {
      const userId = authed(req);
      const id = randomUUID();
      await db.insert(kycSubmissions).values({ id, userId, docType, docUrl: body.docUrl.slice(0, 8_000_000) });
      await db.update(creatorProfiles).set({ kycStatus: "pending", updatedAt: new Date() }).where(eq(creatorProfiles.userId, userId));
      res.json({ success: true, id, status: "pending" });
    } catch (err) {
      httpError(res, err, "Could not submit KYC.");
    }
  });

  app.get("/api/creator/kyc", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db.select().from(kycSubmissions).where(eq(kycSubmissions.userId, authed(req))).orderBy(desc(kycSubmissions.createdAt));
      res.json({ kyc: rows.map((k) => ({ id: k.id, docType: k.docType, status: k.status, reviewerNote: k.reviewerNote, createdAt: k.createdAt.toISOString() })) });
    } catch (err) {
      httpError(res, err, "Could not load KYC status.");
    }
  });

  /** KYC video prompt — the sentence the creator must speak on camera. */
  app.get("/api/creator/kyc-prompt", authenticateToken, requireRole("creator", "agency", "admin"), (_req: Request, res: Response) => {
    const today = new Date().toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" });
    res.json({
      text: `My name is visible on my government ID. Today is ${today}. I am applying to be a MinuteMate creator of my own free will.`,
    });
  });

  app.get("/api/creator/earnings/stats", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const walletRows = await db.select().from(creatorWallets).where(eq(creatorWallets.userId, userId)).limit(1);
      const profile = await db.select().from(creatorProfiles).where(eq(creatorProfiles.userId, userId)).limit(1);
      const recentGifts = await db
        .select({ gift: giftTransactions, user: users })
        .from(giftTransactions)
        .innerJoin(users, eq(users.id, giftTransactions.fromUserId))
        .where(eq(giftTransactions.toCreatorId, userId))
        .orderBy(desc(giftTransactions.createdAt))
        .limit(20);
      const recentCalls = await db
        .select()
        .from(callSessions)
        .where(and(eq(callSessions.creatorId, userId), eq(callSessions.status, "ended")))
        .orderBy(desc(callSessions.createdAt))
        .limit(20);
      const w = walletRows[0];
      res.json({
        balance: w ? Number(w.balancePaise) / 100 : 0,
        balancePaise: w ? Number(w.balancePaise) : 0,
        lifetime: w ? Number(w.lifetimePaise) / 100 : 0,
        totalCalls: profile[0]?.totalCalls ?? 0,
        totalMinutes: profile[0]?.totalMinutes ?? 0,
        rating: profile[0] ? Number(profile[0].rating) / 10 : 0,
        recentGifts: recentGifts.map((r) => ({ id: r.gift.id, amount: Number(r.gift.pricePaise) / 100, from: r.user.name || "User", createdAt: r.gift.createdAt.toISOString() })),
        recentCalls: recentCalls.map((c) => ({ id: c.id, durationSec: c.durationSec, earnings: Number(c.costPaise) / 100, createdAt: c.createdAt.toISOString() })),
      });
    } catch (err) {
      httpError(res, err, "Could not load earnings.");
    }
  });

  app.get("/api/creator/bank", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db.select().from(creatorBankDetails).where(eq(creatorBankDetails.userId, authed(req))).limit(1);
      const b = rows[0];
      res.json({
        bank: b
          ? {
              accountHolder: b.accountHolder,
              accountNumber: b.accountNumber ? "••••" + b.accountNumber.slice(-4) : null,
              ifsc: b.ifsc,
              upiId: b.upiId,
              hasDetails: Boolean(b.upiId || b.accountNumber),
            }
          : { hasDetails: false },
      });
    } catch (err) {
      httpError(res, err, "Could not load bank details.");
    }
  });

  app.post("/api/creator/bank", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const body = (req.body as Record<string, unknown> | undefined) ?? {};
    const upiId = typeof body.upiId === "string" ? body.upiId.trim() : "";
    const accountNumber = typeof body.accountNumber === "string" ? body.accountNumber.replace(/\s/g, "") : "";
    const ifsc = typeof body.ifsc === "string" ? body.ifsc.trim().toUpperCase() : "";
    if (upiId && !/^[\w.-]{2,}@[a-zA-Z]{2,}$/.test(upiId)) {
      res.status(400).json({ error: "Enter a valid UPI ID (e.g. name@upi)." });
      return;
    }
    if (!upiId && !(accountNumber && ifsc)) {
      res.status(400).json({ error: "Add a UPI ID or bank account + IFSC." });
      return;
    }
    if (accountNumber && !/^\d{9,18}$/.test(accountNumber)) {
      res.status(400).json({ error: "Enter a valid bank account number." });
      return;
    }
    if (accountNumber && !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
      res.status(400).json({ error: "Enter a valid IFSC code." });
      return;
    }
    try {
      const userId = authed(req);
      const values = {
        userId,
        accountHolder: typeof body.accountHolder === "string" ? body.accountHolder.trim().slice(0, 80) : null,
        accountNumber: accountNumber || null,
        ifsc: ifsc || null,
        upiId: upiId || null,
        updatedAt: new Date(),
      };
      await db.insert(creatorBankDetails).values(values).onConflictDoUpdate({ target: creatorBankDetails.userId, set: values });
      res.json({ success: true });
    } catch (err) {
      httpError(res, err, "Could not save bank details.");
    }
  });

  app.post("/api/creator/withdraw", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const amountPaise = Math.round(Number((req.body as { amount?: unknown } | undefined)?.amount ?? 0));
    if (!Number.isFinite(amountPaise) || amountPaise < 50000) {
      res.status(400).json({ error: "Minimum withdrawal is ₹500." });
      return;
    }
    try {
      const userId = authed(req);
      const bank = await db.select().from(creatorBankDetails).where(eq(creatorBankDetails.userId, userId)).limit(1);
      const destination = bank[0]?.upiId || (bank[0]?.accountNumber ? `A/C ••${bank[0].accountNumber.slice(-4)} ${bank[0].ifsc}` : "");
      if (!destination) {
        res.status(400).json({ error: "Add your UPI ID or bank details first." });
        return;
      }
      const debited = (await sql(
        `UPDATE creator_wallets SET balance_paise = balance_paise - $1, updated_at = now()
         WHERE user_id = $2 AND balance_paise >= $1 RETURNING balance_paise`,
        [amountPaise, userId],
      )) as Array<{ balance_paise: string }>;
      if (debited.length === 0) {
        res.status(400).json({ error: "Insufficient earnings balance." });
        return;
      }
      const id = randomUUID();
      await db.insert(withdrawals).values({ id, creatorId: userId, amountPaise, destination });
      res.json({ success: true, id, amount: amountPaise / 100, status: "pending", balance: Number(debited[0].balance_paise) / 100 });
    } catch (err) {
      httpError(res, err, "Could not request withdrawal.");
    }
  });

  app.get("/api/creator/withdrawals", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db.select().from(withdrawals).where(eq(withdrawals.creatorId, authed(req))).orderBy(desc(withdrawals.createdAt)).limit(50);
      res.json({ withdrawals: rows.map((w) => ({ id: w.id, amount: Number(w.amountPaise) / 100, destination: w.destination, status: w.status, createdAt: w.createdAt.toISOString() })) });
    } catch (err) {
      httpError(res, err, "Could not load withdrawals.");
    }
  });

  /** Agency: team roster with earnings. */
  app.get("/api/creator/agency/team", authenticateToken, requireRole("agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db
        .select({ user: users, profile: creatorProfiles, wallet: creatorWallets })
        .from(users)
        .innerJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .leftJoin(creatorWallets, eq(creatorWallets.userId, users.id))
        .where(eq(creatorProfiles.agencyId, authed(req)))
        .orderBy(desc(creatorProfiles.totalMinutes))
        .limit(200);
      res.json({
        team: rows.map((r) => ({
          ...creatorCard(r.user, r.profile),
          lifetimeEarnings: r.wallet ? Number(r.wallet.lifetimePaise) / 100 : 0,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load team.");
    }
  });

  // ---------------------------------------------------------- chat (persistent)
  app.post("/api/chat/threads", authenticateToken, async (req: Request, res: Response) => {
    const creatorId = (req.body as { creatorId?: unknown } | undefined)?.creatorId;
    if (typeof creatorId !== "string" || !creatorId) {
      res.status(400).json({ error: "creatorId is required." });
      return;
    }
    try {
      const userId = authed(req);
      const creator = await db
        .select({ user: users, profile: creatorProfiles })
        .from(users)
        .innerJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .where(and(eq(users.id, creatorId), eq(creatorProfiles.verificationStatus, "approved")))
        .limit(1);
      if (!creator[0]) {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      const blocked = await blockedIdsBothWays(userId);
      if (blocked.has(creatorId)) {
        res.status(403).json({ error: "You cannot message this creator." });
        return;
      }
      const id = randomUUID();
      await sql(
        `INSERT INTO chat_threads (id, user_id, creator_id) VALUES ($1, $2, $3)
         ON CONFLICT (user_id, creator_id) DO NOTHING`,
        [id, userId, creatorId],
      );
      const thread = await db.select().from(chatThreads)
        .where(and(eq(chatThreads.userId, userId), eq(chatThreads.creatorId, creatorId))).limit(1);
      res.json({ id: thread[0].id, creatorId, createdAt: thread[0].createdAt.toISOString() });
    } catch (err) {
      httpError(res, err, "Could not open chat.");
    }
  });

  app.get("/api/chat/threads", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const me = await getUserById(userId);
      const iAmCreator = me?.role === "creator" || me?.role === "agency";
      const sideFilter = iAmCreator ? "t.creator_id" : "t.user_id";
      const rows = await sql(
        `SELECT t.id, t.user_id, t.creator_id, t.created_at,
                m.body AS last_body, m.created_at AS last_at,
                cp.display_name AS creator_name, u.name AS user_name
         FROM chat_threads t
         LEFT JOIN LATERAL (
           SELECT body, created_at FROM chat_messages
           WHERE thread_id = t.id ORDER BY created_at DESC LIMIT 1
         ) m ON true
         LEFT JOIN creator_profiles cp ON cp.user_id = t.creator_id
         LEFT JOIN users u ON u.id = t.user_id
         WHERE ${sideFilter} = $1
         ORDER BY m.created_at DESC NULLS LAST, t.created_at DESC
         LIMIT 50`,
        [userId],
      ) as Array<Record<string, unknown>>;
      res.json({
        threads: rows.map((r) => ({
          id: r.id as string,
          creatorId: r.creator_id as string,
          userId: r.user_id as string,
          otherName: iAmCreator
            ? ((r.user_name as string) || "User")
            : ((r.creator_name as string) || "Creator"),
          lastMessage: (r.last_body as string) ?? null,
          lastMessageAt: r.last_at ? new Date(r.last_at as string).toISOString() : null,
          createdAt: new Date(r.created_at as string).toISOString(),
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load chats.");
    }
  });

  async function getThreadFor(userId: string, threadId: string) {
    const rows = await db.select().from(chatThreads).where(eq(chatThreads.id, threadId)).limit(1);
    const t = rows[0];
    if (!t || (t.userId !== userId && t.creatorId !== userId)) return null;
    return t;
  }

  app.get("/api/chat/threads/:id/messages", authenticateToken, async (req: Request, res: Response) => {
    try {
      const t = await getThreadFor(authed(req), req.params.id);
      if (!t) {
        res.status(404).json({ error: "Chat not found." });
        return;
      }
      const msgs = await db.select().from(chatMessages)
        .where(eq(chatMessages.threadId, t.id)).orderBy(chatMessages.createdAt).limit(200);
      res.json({
        messages: msgs.map((m) => ({
          id: m.id,
          senderId: m.senderId,
          senderRole: m.senderRole,
          body: m.body,
          kind: m.kind,
          giftId: m.giftId,
          createdAt: m.createdAt.toISOString(),
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load messages.");
    }
  });

  app.post("/api/chat/threads/:id/messages", authenticateToken, async (req: Request, res: Response) => {
    const body = typeof (req.body as { body?: unknown } | undefined)?.body === "string"
      ? (req.body as { body: string }).body.trim() : "";
    if (!body || body.length > 2000) {
      res.status(400).json({ error: "Message must be 1–2000 characters." });
      return;
    }
    try {
      const userId = authed(req);
      const t = await getThreadFor(userId, req.params.id);
      if (!t) {
        res.status(404).json({ error: "Chat not found." });
        return;
      }
      const blocked = await blockedIdsBothWays(userId);
      const other = t.userId === userId ? t.creatorId : t.userId;
      if (blocked.has(other)) {
        res.status(403).json({ error: "You cannot message this user." });
        return;
      }
      const me = await getUserById(userId);
      const id = randomUUID();
      const now = new Date();
      await db.insert(chatMessages).values({
        id, threadId: t.id, senderId: userId,
        senderRole: me?.role === "creator" ? "creator" : "user",
        body: body.slice(0, 2000), kind: "text",
      });
      await db.update(chatThreads).set({ lastMessageAt: now }).where(eq(chatThreads.id, t.id));
      res.json({ id, createdAt: now.toISOString() });
    } catch (err) {
      httpError(res, err, "Could not send message.");
    }
  });

  // ---------------------------------------------------------- blocks (persistent)
  app.post("/api/blocks", authenticateToken, async (req: Request, res: Response) => {
    const creatorId = (req.body as { creatorId?: unknown } | undefined)?.creatorId;
    if (typeof creatorId !== "string" || !creatorId) {
      res.status(400).json({ error: "creatorId is required." });
      return;
    }
    try {
      const userId = authed(req);
      if (creatorId === userId) {
        res.status(400).json({ error: "You cannot block yourself." });
        return;
      }
      const target = await getUserById(creatorId);
      if (!target) {
        res.status(404).json({ error: "User not found." });
        return;
      }
      await db.insert(blocks).values({ blockerId: userId, blockedId: creatorId }).onConflictDoNothing();
      // Cancel any ringing sessions between the two.
      await sql(
        `UPDATE call_sessions SET status = 'cancelled', ended_at = now()
         WHERE status = 'ringing' AND
           ((user_id = $1 AND creator_id = $2) OR (user_id = $2 AND creator_id = $1))`,
        [userId, creatorId],
      );
      res.json({ success: true, creatorId, blocked: true });
    } catch (err) {
      httpError(res, err, "Could not block.");
    }
  });

  app.delete("/api/blocks/:creatorId", authenticateToken, async (req: Request, res: Response) => {
    try {
      await db.delete(blocks).where(
        and(eq(blocks.blockerId, authed(req)), eq(blocks.blockedId, req.params.creatorId)),
      );
      res.json({ success: true, creatorId: req.params.creatorId, blocked: false });
    } catch (err) {
      httpError(res, err, "Could not unblock.");
    }
  });

  app.get("/api/blocks", authenticateToken, async (req: Request, res: Response) => {
    try {
      const rows = await db
        .select({ block: blocks, user: users, profile: creatorProfiles })
        .from(blocks)
        .innerJoin(users, eq(users.id, blocks.blockedId))
        .leftJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .where(eq(blocks.blockerId, authed(req)))
        .orderBy(desc(blocks.createdAt));
      res.json({
        blocked: rows.map((r) => ({
          creatorId: r.user.id,
          name: r.profile?.displayName ?? r.user.name ?? "User",
          avatarUrl: r.profile?.avatarUrl ?? null,
          blockedAt: r.block.createdAt.toISOString(),
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load blocked list.");
    }
  });

  // ---------------------------------------------------------- calls (persistent + billed)
  app.post("/api/call/sessions", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { creatorId?: unknown; callType?: unknown } | undefined) ?? {};
    const creatorId = typeof body.creatorId === "string" ? body.creatorId : "";
    const callType = body.callType === "audio" ? "audio" : "video";
    if (!creatorId) {
      res.status(400).json({ error: "creatorId is required." });
      return;
    }
    try {
      const userId = authed(req);
      if (creatorId === userId) {
        res.status(400).json({ error: "You cannot call yourself." });
        return;
      }
      const rows = await db
        .select({ user: users, profile: creatorProfiles })
        .from(users)
        .innerJoin(creatorProfiles, eq(creatorProfiles.userId, users.id))
        .where(and(eq(users.id, creatorId), eq(creatorProfiles.verificationStatus, "approved"), eq(users.status, "active")))
        .limit(1);
      const row = rows[0];
      if (!row) {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      const blocked = await blockedIdsBothWays(userId);
      if (blocked.has(creatorId)) {
        res.status(403).json({ error: "You cannot call this creator." });
        return;
      }
      if (!row.profile.isOnline) {
        res.status(409).json({ error: `${row.profile.displayName} is offline right now. Try again later.`, offline: true });
        return;
      }
      if (row.profile.allowedCallTypes !== "both" && row.profile.allowedCallTypes !== callType) {
        res.status(409).json({ error: `This creator only accepts ${row.profile.allowedCallTypes} calls.` });
        return;
      }
      const ratePaise = Number(row.profile.pricePerMinPaise);
      const wallet = await getWalletSummary(userId);
      if (wallet.balancePaise < ratePaise) {
        res.status(402).json({
          error: `Insufficient balance. You need at least ₹${(ratePaise / 100).toFixed(0)} for 1 minute.`,
          code: "INSUFFICIENT_BALANCE",
          insufficient: true,
          balance: wallet.balance,
        });
        return;
      }
      const id = randomUUID();
      const roomId = `room_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
      await db.insert(callSessions).values({
        id, userId, creatorId, roomId, callType, status: "ringing", ratePaisePerMin: ratePaise,
      });
      res.json({
        sessionId: id,
        roomId,
        creatorId,
        creatorName: row.profile.displayName,
        callType,
        pricePerMinute: ratePaise / 100,
        status: "ringing",
      });
    } catch (err) {
      httpError(res, err, "Could not start the call.");
    }
  });

  app.get("/api/call/sessions/:id", authenticateToken, async (req: Request, res: Response) => {
    try {
      await sweepStaleRinging(req.params.id);
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, req.params.id)).limit(1);
      const s = rows[0];
      const userId = authed(req);
      if (!s || (s.userId !== userId && s.creatorId !== userId)) {
        res.status(404).json({ error: "Call not found." });
        return;
      }
      res.json(sessionView(s));
    } catch (err) {
      httpError(res, err, "Could not load call.");
    }
  });

  app.post("/api/call/sessions/:id/heartbeat", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, req.params.id)).limit(1);
      const s = rows[0];
      if (!s || (s.userId !== userId && s.creatorId !== userId)) {
        res.status(404).json({ error: "Call not found." });
        return;
      }
      if (s.status === "ringing" && s.createdAt.getTime() < Date.now() - 90_000) {
        // Guard the status so we don't clobber a session that settleCall
        // (or the creator) just claimed.
        await sql(
          `UPDATE call_sessions SET status = 'missed', ended_at = now()
           WHERE id = $1 AND status = 'ringing'`,
          [s.id],
        );
        res.json({ success: true, status: "missed" });
        return;
      }
      if (s.status === "active") {
        // Safety: end the call server-side if the user's balance ran dry.
        const wallet = await getWalletSummary(s.userId);
        if (wallet.balancePaise < Number(s.ratePaisePerMin)) {
          await settleCall(s.id);
          res.json({ success: true, status: "ended", reason: "insufficient_balance" });
          return;
        }
      }
      await db.update(callSessions).set({ lastHeartbeatAt: new Date() }).where(eq(callSessions.id, s.id));
      res.json({ success: true, status: s.status });
    } catch (err) {
      httpError(res, err, "Heartbeat failed.");
    }
  });

  app.post("/api/call/sessions/:id/accept", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, req.params.id)).limit(1);
      const s = rows[0];
      if (!s || s.creatorId !== authed(req)) {
        res.status(404).json({ error: "Call not found." });
        return;
      }
      if (s.status !== "ringing") {
        res.status(409).json({ error: `Call is already ${s.status}.` });
        return;
      }
      await db.update(callSessions)
        .set({ status: "active", startedAt: new Date(), lastHeartbeatAt: new Date() })
        .where(eq(callSessions.id, s.id));
      const updated = await db.select().from(callSessions).where(eq(callSessions.id, s.id)).limit(1);
      res.json({ success: true, ...sessionView(updated[0]) });
    } catch (err) {
      httpError(res, err, "Could not accept the call.");
    }
  });

  app.post("/api/call/sessions/:id/reject", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    try {
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, req.params.id)).limit(1);
      const s = rows[0];
      if (!s || s.creatorId !== authed(req)) {
        res.status(404).json({ error: "Call not found." });
        return;
      }
      if (s.status !== "ringing") {
        res.status(409).json({ error: `Call is already ${s.status}.` });
        return;
      }
      await db.update(callSessions).set({ status: "rejected", endedAt: new Date() }).where(eq(callSessions.id, s.id));
      res.json({ success: true, status: "rejected" });
    } catch (err) {
      httpError(res, err, "Could not reject the call.");
    }
  });

  /** Bill a finished call: debit user, credit creator, update totals. Idempotent-ish. */
  async function settleCall(sessionId: string): Promise<{ durationSec: number; costPaise: number } | null> {
    // RACE FIX (2026-09-28): claim the session atomically — concurrent /end
    // requests (user hangup + creator hangup + heartbeat timeout) must not
    // double-debit. Only the request whose UPDATE flips the status proceeds.
    const claimed = (await sql(
      `UPDATE call_sessions
       SET status = 'settling'
       WHERE id = $1 AND status IN ('ringing', 'active')
       RETURNING id, user_id, creator_id, rate_paise_per_min, started_at`,
      [sessionId],
    )) as Array<Record<string, unknown>>;
    if (claimed.length === 0) {
      // Another request already settled (or is settling) this session —
      // return the recorded final state instead of charging again.
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, sessionId)).limit(1);
      const s = rows[0];
      if (!s) return null;
      return { durationSec: s.durationSec ?? 0, costPaise: Number(s.costPaise ?? 0) };
    }
    const s = claimed[0];
    const userId = s.user_id as string;
    const creatorId = s.creator_id as string;
    const ratePaisePerMin = Number(s.rate_paise_per_min ?? 0);
    const startedAt = s.started_at ? new Date(s.started_at as string) : null;
    const endedAt = new Date();
    if (!startedAt) {
      // Never answered — no charge.
      await db
        .update(callSessions)
        .set({ status: "cancelled", endedAt })
        .where(eq(callSessions.id, sessionId));
      return { durationSec: 0, costPaise: 0 };
    }
    const durationSec = Math.max(0, Math.round((endedAt.getTime() - startedAt.getTime()) / 1000));
    const billableMin = Math.max(1, Math.ceil(durationSec / 60));
    const fullCost = billableMin * ratePaisePerMin;
    // Debit what is available (never negative).
    let debited = await debitUserWallet(userId, fullCost);
    let actual = fullCost;
    if (debited === null) {
      const w = await getWalletSummary(userId);
      actual = w.balancePaise;
      if (actual > 0) {
        await sql(`UPDATE wallets SET balance_paise = 0, updated_at = now() WHERE user_id = $1`, [userId]);
      }
    }
    if (actual > 0) {
      await recordWalletTransaction(userId, "call_debit", -actual, `Call with creator (${billableMin} min)`);
      await creditCreatorEarnings(creatorId, actual);
    }
    await db
      .update(callSessions)
      .set({ status: "ended", durationSec, costPaise: actual, endedAt })
      .where(eq(callSessions.id, sessionId));
    await sql(
      `UPDATE creator_profiles SET total_calls = total_calls + 1, total_minutes = total_minutes + $1, updated_at = now() WHERE user_id = $2`,
      [billableMin, creatorId],
    );
    return { durationSec, costPaise: actual };
  }

  app.post("/api/call/sessions/:id/end", authenticateToken, async (req: Request, res: Response) => {
    try {
      const userId = authed(req);
      const rows = await db.select().from(callSessions).where(eq(callSessions.id, req.params.id)).limit(1);
      const s = rows[0];
      if (!s || (s.userId !== userId && s.creatorId !== userId)) {
        res.status(404).json({ error: "Call not found." });
        return;
      }
      if (s.status === "ended" || s.status === "rejected" || s.status === "missed" || s.status === "cancelled") {
        res.json({ success: true, sessionId: s.id, status: s.status, durationSec: s.durationSec, cost: Number(s.costPaise) / 100 });
        return;
      }
      const settled = await settleCall(s.id);
      res.json({
        success: true,
        sessionId: s.id,
        status: s.startedAt ? "ended" : "cancelled",
        durationSec: settled?.durationSec ?? 0,
        cost: (settled?.costPaise ?? 0) / 100,
      });
    } catch (err) {
      httpError(res, err, "Could not end the call.");
    }
  });

  // ---------------------------------------------------------- gifts
  app.get("/api/gifts", authenticateToken, async (_req: Request, res: Response) => {
    try {
      const rows = await db.select().from(gifts).orderBy(gifts.sortOrder);
      res.json({
        gifts: rows.map((g) => ({ id: g.id, name: g.name, emoji: g.emoji, price: Number(g.pricePaise) / 100, pricePaise: Number(g.pricePaise) })),
      });
    } catch (err) {
      httpError(res, err, "Could not load gifts.");
    }
  });

  app.post("/api/gifts/send", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { creatorId?: unknown; giftId?: unknown; callSessionId?: unknown } | undefined) ?? {};
    const creatorId = typeof body.creatorId === "string" ? body.creatorId : "";
    const giftId = typeof body.giftId === "string" ? body.giftId : "";
    if (!creatorId || !giftId) {
      res.status(400).json({ error: "creatorId and giftId are required." });
      return;
    }
    try {
      const userId = authed(req);
      const giftRows = await db.select().from(gifts).where(eq(gifts.id, giftId)).limit(1);
      const gift = giftRows[0];
      if (!gift) {
        res.status(404).json({ error: "Gift not found." });
        return;
      }
      const creator = await getUserById(creatorId);
      if (!creator || creator.role === "user") {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      const pricePaise = Number(gift.pricePaise);
      const newBalance = await debitUserWallet(userId, pricePaise);
      if (newBalance === null) {
        res.status(402).json({ error: "Insufficient balance. Please recharge.", insufficient: true });
        return;
      }
      await recordWalletTransaction(userId, "gift", -pricePaise, `Sent ${gift.name} ${gift.emoji}`);
      await creditCreatorEarnings(creatorId, pricePaise);
      const id = randomUUID();
      await db.insert(giftTransactions).values({
        id, fromUserId: userId, toCreatorId: creatorId, giftId,
        pricePaise, callSessionId: typeof body.callSessionId === "string" ? body.callSessionId : null,
      });
      res.json({ success: true, id, balance: newBalance / 100, balancePaise: newBalance });
    } catch (err) {
      httpError(res, err, "Could not send gift.");
    }
  });

  // ---------------------------------------------------------- uploads
  // Trial mode: validated data URLs. Move to object storage before scale.
  app.post("/api/upload/avatar", authenticateToken, async (req: Request, res: Response) => {
    const dataUrl = (req.body as { dataUrl?: unknown } | undefined)?.dataUrl;
    const check = validateDataUrl(dataUrl, { imagesOnly: true, maxBytes: 5 * 1024 * 1024 });
    if (typeof check === "string") {
      res.status(400).json({ error: check });
      return;
    }
    res.json({ success: true, url: dataUrl });
  });

  app.post("/api/upload/kyc", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const body = (req.body as { docType?: unknown; dataUrl?: unknown } | undefined) ?? {};
    const docType = typeof body.docType === "string" ? body.docType : "";
    if (!["aadhaar", "pan", "selfie"].includes(docType)) {
      res.status(400).json({ error: "Invalid document type." });
      return;
    }
    const check = validateDataUrl(body.dataUrl, { imagesOnly: true, maxBytes: 5 * 1024 * 1024 });
    if (typeof check === "string") {
      res.status(400).json({ error: check });
      return;
    }
    try {
      const userId = authed(req);
      const id = randomUUID();
      await db.insert(kycSubmissions).values({ id, userId, docType, docUrl: body.dataUrl as string });
      await db.update(creatorProfiles).set({ kycStatus: "pending", updatedAt: new Date() }).where(eq(creatorProfiles.userId, userId));
      res.json({ success: true, id, status: "pending" });
    } catch (err) {
      httpError(res, err, "Could not upload document.");
    }
  });

  app.post("/api/upload/kyc-video", authenticateToken, requireRole("creator", "agency", "admin"), async (req: Request, res: Response) => {
    const dataUrl = (req.body as { dataUrl?: unknown } | undefined)?.dataUrl;
    const check = validateDataUrl(dataUrl, { imagesOnly: false, maxBytes: 6 * 1024 * 1024 });
    if (typeof check === "string") {
      res.status(400).json({ error: check });
      return;
    }
    try {
      const userId = authed(req);
      const id = randomUUID();
      await db.insert(kycSubmissions).values({ id, userId, docType: "video", docUrl: dataUrl as string });
      await db.update(creatorProfiles).set({ kycStatus: "pending", updatedAt: new Date() }).where(eq(creatorProfiles.userId, userId));
      res.json({ success: true, id, status: "pending" });
    } catch (err) {
      httpError(res, err, "Could not upload video.");
    }
  });
}
