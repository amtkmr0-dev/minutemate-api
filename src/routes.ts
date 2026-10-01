/**
 * MinuteMate API — Express route definitions.
 *
 * Endpoint contracts (kept compatible with the MinuteMate mobile client):
 *
 *   AUTH
 *   POST /api/auth/send-otp        { phone } -> { success, message } | 400 { error }
 *   POST /api/auth/verify-otp      { phone, otp } -> { accessToken, token, refreshToken, user }
 *   POST /api/auth/refresh         { refreshToken } -> { accessToken, refreshToken }
 *   POST /api/auth/logout          { refreshToken } -> { success }
 *
 *   PAYMENTS (Razorpay)
 *   POST /api/payments/create-order    (auth) { amount } -> { order_id, amount, currency, key_id, simulated? }
 *   POST /api/payments/verify         (auth) { razorpay_payment_id, razorpay_order_id, razorpay_signature }
 *                                          -> { success, duplicate?, balance, amount, bonus, total, transactionId }
 *   POST /api/payments/simulate-success (auth, simulation mode only) { orderId } -> verify-shaped result
 *   GET  /api/payments/packs          -> server-side pack list + bonus tiers (for UI rendering)
 *
 *   WALLET
 *   GET /api/wallet/me[ /transactions] (auth) — primary client paths
 *   GET /api/wallet[/transactions]     (auth) — aliases
 *
 *   HEALTH
 *   GET /api/health -> { status: "ok" }
 */

import type { Express, Request, Response } from "express";
import express from "express";
import { eq } from "drizzle-orm";
import { db, sql } from "./db.js";
import { users } from "./schema.js";
import {
  authenticateToken,
  issueOtp,
  normalizeIndianMobile,
  revokeRefreshToken,
  rotateRefreshToken,
  signAccessToken,
  signRefreshToken,
  verifyOtp,
  type AuthenticatedRequest,
} from "./auth.js";
import {
  BONUS_TIERS,
  RECHARGE_PACKS,
  createRechargeOrder,
  getUserById,
  isSimulationAllowed,
  PaymentNotConfiguredError,
  simulateSuccessfulPayment,
  verifyAndCreditPayment,
} from "./payments.js";
import { getTransactionHistory, getWalletSummary } from "./wallet.js";
import crypto from "node:crypto";

function httpError(res: Response, err: unknown, fallback: string): void {
  const status = (err as { statusCode?: number })?.statusCode ?? 500;
  const message = err instanceof Error ? err.message : fallback;
  res.status(status).json({ error: message });
}

/**
 * ZEGOCLOUD Token04 generation — port of the official zego_server_assistant
 * (token/nodejs/server/zegoServerAssistant.js, MIT). Token = "04" + base64(
 *   expire:8 BE + ivLen:2 BE + iv + encLen:2 BE + AES-CBC(tokenInfo JSON)
 * ).
 */
function generateZegoToken04(
  appId: number,
  userId: string,
  secret: string,
  effectiveTimeInSeconds: number,
  payload: string
): string {
  if (!appId || typeof appId !== "number") throw new Error("appID invalid");
  if (!userId || typeof userId !== "string") throw new Error("userId invalid");
  if (!secret || typeof secret !== "string" || secret.length !== 32)
    throw new Error("secret must be a 32 byte string");
  if (!effectiveTimeInSeconds || typeof effectiveTimeInSeconds !== "number")
    throw new Error("effectiveTimeInSeconds invalid");

  const createTime = Math.floor(Date.now() / 1000);
  const tokenInfo = {
    app_id: appId,
    user_id: userId,
    nonce: Math.floor(Math.random() * 4294967296) - 2147483648,
    ctime: createTime,
    expire: createTime + effectiveTimeInSeconds,
    payload: payload || "",
  };
  const plainText = JSON.stringify(tokenInfo);

  const ivChars = "0123456789abcdefghijklmnopqrstuvwxyz";
  let iv = "";
  for (let i = 0; i < 16; i++) iv += ivChars[Math.floor(Math.random() * ivChars.length)];

  const key = Buffer.from(secret, "utf8");
  const algorithm = key.length === 16 ? "aes-128-cbc" : key.length === 24 ? "aes-192-cbc" : "aes-256-cbc";
  const cipher = crypto.createCipheriv(algorithm, key, Buffer.from(iv, "utf8"));
  const encrypted = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);

  const expireBuf = Buffer.alloc(8);
  expireBuf.writeBigInt64BE(BigInt(tokenInfo.expire));
  const ivLenBuf = Buffer.alloc(2);
  ivLenBuf.writeUInt16BE(iv.length);
  const encLenBuf = Buffer.alloc(2);
  encLenBuf.writeUInt16BE(encrypted.length);
  const buf = Buffer.concat([expireBuf, ivLenBuf, Buffer.from(iv, "utf8"), encLenBuf, encrypted]);
  return "04" + buf.toString("base64");
}

function publicUser(user: { id: string; phone: string; name: string | null; email: string | null }) {
  return { id: user.id, phone: user.phone, name: user.name, email: user.email };
}

export function registerRoutes(app: Express): void {
  // ------------------------------------------------------------------ health
  app.get("/api/health", (_req: Request, res: Response) => {
    res.json({ status: "ok" });
  });

  // ------------------------------------------------------------------ auth

  /**
   * Send an OTP to an Indian mobile number.
   * Valid: 10 digits starting 6-9 (accepts +91 / 91 / 0 prefixes, spaces).
   */
  app.post("/api/auth/send-otp", async (req: Request, res: Response) => {
    const phone = normalizeIndianMobile((req.body as { phone?: unknown } | undefined)?.phone);
    if (!phone) {
      res.status(400).json({ error: "Invalid phone number" });
      return;
    }
    try {
      const { otp } = await issueOtp(phone);
      // Production: send `otp` via the SMS provider here (MSG91/Twilio/Exotel).
      // Dev: log it so the flow is testable without an SMS provider.
      if (process.env.NODE_ENV !== "production") {
        console.log(`[otp] ${phone} -> ${otp}`);
      }
      res.json({ success: true, message: "OTP sent successfully" });
    } catch (err: any) {
      // BUG 13 fix (2026-09-30): return 429 for cooldown violations so the
      // client can show a "wait X seconds" message instead of a generic error.
      if (err?.message?.includes("Please wait")) {
        res.status(429).json({ error: err.message });
        return;
      }
      httpError(res, err, "Could not send OTP. Please try again.");
    }
  });

  /**
   * Dev/testing — retrieve the current OTP for a phone number.
   * Only for testing until SMS is configured. DELETE THIS before production launch.
   */
  app.get("/api/auth/dev-otp", async (req: Request, res: Response) => {    const secret = req.query.secret as string;
    // Temporary testing secret — remove endpoint before production
    if (secret !== "mm-test-2026") {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    const phone = normalizeIndianMobile(req.query.phone);
    if (!phone) {
      res.status(400).json({ error: "Invalid phone number" });
      return;
    }
    try {
      // Generate a fresh OTP and return it directly (testing only).
      const { otp } = await issueOtp(phone);
      res.json({ success: true, phone, otp });
    } catch (err) {
      httpError(res, err, "Could not retrieve OTP");
    }
  });

  /** Verify the OTP and issue a session. Creates the user on first login. */
  app.post("/api/auth/verify-otp", async (req: Request, res: Response) => {
    const body = (req.body as { phone?: unknown; otp?: unknown } | undefined) ?? {};
    const phone = normalizeIndianMobile(body.phone);
    if (!phone) {
      res.status(400).json({ error: "Invalid phone number" });
      return;
    }
    try {
      const result = await verifyOtp(phone, String(body.otp ?? ""));
      if (!result.ok) {
        res.status(result.status).json({ error: result.error });
        return;
      }
      const accessToken = signAccessToken(result.userId);
      const refreshToken = await signRefreshToken(result.userId);
      const user = await getUserById(result.userId);
      res.json({
        success: true,
        isNewUser: result.isNewUser,
        accessToken,
        token: accessToken, // alias — some clients read `token`
        refreshToken,
        user: user ? publicUser(user) : { id: result.userId, phone },
      });
    } catch (err) {
      httpError(res, err, "Could not verify OTP. Please try again.");
    }
  });

  /**
   * BUG 9 fix (2026-09-30): Admin OTP login endpoints. The admin web app
   * calls POST /api/auth/admin/request-otp then POST /api/auth/admin/verify,
   * but these endpoints did not exist — requests returned the SPA's index.html,
   * breaking admin login entirely.
   *
   * Security: only users with role='admin' can request/verify. The response
   * is intentionally generic to prevent admin phone enumeration.
   */
  app.post("/api/auth/admin/request-otp", async (req: Request, res: Response) => {
    const body = (req.body as { mobile?: unknown } | undefined) ?? {};
    const phone = normalizeIndianMobile(body.mobile);
    if (!phone) {
      res.status(400).json({ error: "Invalid phone number" });
      return;
    }
    try {
      // Check if this phone belongs to an admin. Use generic response
      // to prevent enumeration.
      const adminUser = await db.select().from(users).where(eq(users.phone, phone)).limit(1);
      if (!adminUser[0] || adminUser[0].role !== "admin") {
        // Generic response — don't reveal whether this is an admin number.
        // Still issue a dummy delay to prevent timing attacks.
        await new Promise((resolve) => setTimeout(resolve, 500));
        res.json({ success: true, message: "If this is an admin number, an OTP has been sent." });
        return;
      }
      const { otp } = await issueOtp(phone);
      if (process.env.NODE_ENV !== "production") {
        console.log(`[admin-otp] ${phone} -> ${otp}`);
      }
      res.json({ success: true, message: "OTP sent successfully" });
    } catch (err: any) {
      // BUG 13 fix (2026-09-30): 429 for cooldown.
      if (err?.message?.includes("Please wait")) {
        res.status(429).json({ error: err.message });
        return;
      }
      httpError(res, err, "Could not send OTP. Please try again.");
    }
  });

  app.post("/api/auth/admin/verify", async (req: Request, res: Response) => {
    const body = (req.body as { mobile?: unknown; otp?: unknown } | undefined) ?? {};
    const phone = normalizeIndianMobile(body.mobile);
    if (!phone) {
      res.status(400).json({ error: "Invalid phone number" });
      return;
    }
    try {
      // Verify the user is an admin BEFORE checking OTP.
      const adminUser = await db.select().from(users).where(eq(users.phone, phone)).limit(1);
      if (!adminUser[0] || adminUser[0].role !== "admin") {
        res.status(403).json({ error: "Access denied." });
        return;
      }
      const result = await verifyOtp(phone, String(body.otp ?? ""));
      if (!result.ok) {
        res.status(result.status).json({ error: result.error });
        return;
      }
      // Double-check the verified user is still an admin (role could have changed).
      const verifiedUser = await getUserById(result.userId);
      if (!verifiedUser || verifiedUser.role !== "admin") {
        res.status(403).json({ error: "Access denied." });
        return;
      }
      const accessToken = signAccessToken(result.userId);
      const refreshToken = await signRefreshToken(result.userId);
      res.json({
        success: true,
        accessToken,
        token: accessToken,
        refreshToken,
        user: {
          id: verifiedUser.id,
          phone: verifiedUser.phone,
          name: verifiedUser.name,
          role: verifiedUser.role,
        },
      });
    } catch (err) {
      httpError(res, err, "Could not verify OTP. Please try again.");
    }
  });

  /** Rotate a refresh token into a fresh access + refresh pair. */
  app.post("/api/auth/refresh", async (req: Request, res: Response) => {
    const token = (req.body as { refreshToken?: unknown } | undefined)?.refreshToken;
    if (typeof token !== "string" || token.length === 0) {
      res.status(400).json({ error: "refreshToken is required" });
      return;
    }
    try {
      const rotated = await rotateRefreshToken(token);
      if (!rotated) {
        res.status(401).json({ error: "Invalid or expired session. Please log in again." });
        return;
      }
      res.json({ accessToken: rotated.accessToken, token: rotated.accessToken, refreshToken: rotated.refreshToken });
    } catch (err) {
      httpError(res, err, "Could not refresh session.");
    }
  });

  /** Logout — revoke the refresh token. The short-lived access token expires on its own. */
  app.post("/api/auth/logout", async (req: Request, res: Response) => {
    try {
      const header = req.headers.authorization;
      const bearer = header?.startsWith("Bearer ") ? header.slice(7) : null;
      const bodyToken = (req.body as { refreshToken?: unknown } | undefined)?.refreshToken;
      // Accept either the refresh token in the body or a refresh-typed bearer.
      const candidate = typeof bodyToken === "string" ? bodyToken : bearer;
      if (candidate) {
        try {
          const { default: jwt } = await import("jsonwebtoken");
          const secret = process.env.JWT_SECRET || "dev-only-insecure-secret-change-me";
          const payload = jwt.verify(candidate, secret) as { typ?: string; jti?: string };
          if (payload.typ === "refresh" && payload.jti) {
            await revokeRefreshToken(payload.jti);
          }
        } catch {
          // Best effort — an invalid token means there is nothing to revoke.
        }
      }
      res.json({ success: true, message: "Logged out" });
    } catch (err) {
      httpError(res, err, "Could not log out.");
    }
  });

  // ------------------------------------------------------------------ payments

  /** Public pack list so the client can render amounts + bonuses without hardcoding them. */
  app.get("/api/payments/packs", (_req: Request, res: Response) => {
    res.json({
      packs: RECHARGE_PACKS.map((p) => ({ packId: p.packId, label: p.label, amount: p.amountPaise / 100 })),
      bonusTiers: BONUS_TIERS,
    });
  });

  /**
   * Step 1 — create a Razorpay order for a rupee amount.
   * The amount is validated against the server-side pack list.
   */
  app.post("/api/payments/create-order", authenticateToken, async (req: Request, res: Response) => {
    const userId = (req as AuthenticatedRequest).userId;
    const rawAmount = (req.body as { amount?: unknown } | undefined)?.amount;
    try {
      const created = await createRechargeOrder(Number(rawAmount), userId);
      res.json({
        order_id: created.orderId,
        amount: created.amountPaise, // paise, as Razorpay expects
        currency: created.currency,
        key_id: created.keyId, // PUBLIC key id only — never the secret
        ...(created.simulated ? { simulated: true } : {}),
      });
    } catch (err) {
      if (err instanceof PaymentNotConfiguredError) {
        res.status(500).json({ error: err.message });
        return;
      }
      const isValidation = /amount|pack/i.test(err instanceof Error ? err.message : "");
      const status = (err as { statusCode?: number }).statusCode ?? (isValidation ? 400 : 500);
      const message =
        err instanceof Error ? err.message : "Could not start the payment. Please try again.";
      res.status(status).json({ error: message });
    }
  });

  /**
   * Step 3 — verify the Razorpay checkout payload and credit the wallet
   * exactly once (idempotent).
   */
  app.post("/api/payments/verify", authenticateToken, async (req: Request, res: Response) => {
    const userId = (req as AuthenticatedRequest).userId;
    const body = (req.body as Record<string, unknown> | undefined) ?? {};
    const razorpay_payment_id = body.razorpay_payment_id;
    const razorpay_order_id = body.razorpay_order_id;
    const razorpay_signature = body.razorpay_signature;
    if (
      typeof razorpay_payment_id !== "string" ||
      typeof razorpay_order_id !== "string" ||
      typeof razorpay_signature !== "string"
    ) {
      res.status(400).json({
        error: "razorpay_payment_id, razorpay_order_id and razorpay_signature are required",
      });
      return;
    }
    try {
      const result = await verifyAndCreditPayment({
        authenticatedUserId: userId,
        razorpayOrderId: razorpay_order_id,
        razorpayPaymentId: razorpay_payment_id,
        razorpaySignature: razorpay_signature,
      });
      res.json(result);
    } catch (err) {
      httpError(res, err, "Payment verification failed. If money was debited, it will be refunded by your bank.");
    }
  });

  /**
   * Dev-only — complete a SIM_ order without the Razorpay dashboard.
   * Only works when PAYMENTS_MODE=simulation (never in production unless
   * explicitly enabled); otherwise 403.
   */
  app.post("/api/payments/simulate-success", authenticateToken, async (req: Request, res: Response) => {
    if (!isSimulationAllowed()) {
      res.status(403).json({ error: "Payment simulation is not enabled on this server" });
      return;
    }
    const userId = (req as AuthenticatedRequest).userId;
    const orderId = (req.body as { orderId?: unknown } | undefined)?.orderId;
    if (typeof orderId !== "string" || orderId.length === 0) {
      res.status(400).json({ error: "orderId is required" });
      return;
    }
    try {
      const result = await simulateSuccessfulPayment({ authenticatedUserId: userId, orderId });
      res.json(result);
    } catch (err) {
      httpError(res, err, "Simulation failed");
    }
  });

  // ------------------------------------------------------------------ wallet

  const walletHandler = async (req: Request, res: Response) => {
    const userId = (req as AuthenticatedRequest).userId;
    try {
      const summary = await getWalletSummary(userId);
      res.json({ balance: summary.balance, balancePaise: summary.balancePaise });
    } catch (err) {
      httpError(res, err, "Could not load wallet.");
    }
  };
  app.get("/api/wallet/me", authenticateToken, walletHandler);
  app.get("/api/wallet", authenticateToken, walletHandler);

  const transactionsHandler = async (req: Request, res: Response) => {
    const userId = (req as AuthenticatedRequest).userId;
    try {
      const limit = Number((req.query as { limit?: string }).limit) || 50;
      const history = await getTransactionHistory(userId, limit);
      res.json({ transactions: history });
    } catch (err) {
      httpError(res, err, "Could not load transactions.");
    }
  };
  app.get("/api/wallet/me/transactions", authenticateToken, transactionsHandler);
  app.get("/api/wallet/transactions", authenticateToken, transactionsHandler);

  // --- Stub endpoints for app functionality (2026-09-28) ---
  // These provide minimal responses so the app's call/chat/block flows work
  // for testing. Replace with real implementations before production.

  /** Public settings (zego config, rates) */
  app.get("/api/settings/public", (_req: Request, res: Response) => {
    res.json({
      zegoAppId: Number(process.env.ZEGO_APP_ID || "0"),
      // Frontend uses server-generated tokens; appId 0 = unconfigured
      callRates: { audio: 30, video: 50 },
      minRecharge: 100,
    });
  });

  /* Call sessions, chat, and blocks are implemented persistently in creator.ts. */

  /**
   * Zego token — real Token04 generation (ZEGOCLOUD zego_server_assistant algorithm).
   * Requires ZEGO_APP_ID and ZEGO_SERVER_SECRET env vars on the server.
   * Without them, returns unconfigured:true so the app shows a notice.
   */
  app.post("/api/zego/token", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { sessionId?: string } | undefined) ?? {};
    const appId = Number(process.env.ZEGO_APP_ID || "0");
    const serverSecret = process.env.ZEGO_SERVER_SECRET || "";
    const userId = (req as AuthenticatedRequest).userId;
    const zegoUserId = `user_${userId}`;
    const roomId = body.sessionId || `room_${Date.now()}`;
    if (!appId || !serverSecret) {
      // Dummy mode: return a placeholder so the UI flow can be tested.
      // The Zego SDK will fail to connect with this, which is expected
      // until real credentials are added.
      res.json({
        appId: 0,
        serverUrl: "",
        token: "dummy-zego-token-unconfigured",
        userId: zegoUserId,
        roomId,
        // Flag so the app can show "video unavailable" instead of crashing
        unconfigured: true,
        message: "Zego not configured. Add ZEGO_APP_ID and ZEGO_SERVER_SECRET to enable video calls.",
      });
      return;
    }
    try {
      // RTC-room payload: allow loginRoom (1) + publishStream (2)
      const payload = JSON.stringify({
        room_id: roomId,
        privilege: { 1: 1, 2: 1 },
        stream_id_list: null,
      });
      const token = generateZegoToken04(appId, zegoUserId, serverSecret, 3600, payload);
      // 2026-09-29: serverUrl was hardcoded to "" which broke all Zego media
      // connections (user saw "Couldn't Start Call", creator saw "Demo call mode").
      // Use ZEGO_SERVER_URL from env, falling back to the standard ZegoCloud
      // WebSocket pattern for this AppID.
      const serverUrl =
        process.env.ZEGO_SERVER_URL || `wss://webliveroom${appId}-api.zegocloud.com/ws`;
      res.json({ appId, serverUrl, token, userId: zegoUserId, roomId, expiresIn: 3600 });
    } catch (err) {
      httpError(res, err, "Could not generate call token.");
    }
  });

  /* Chat threads and blocks are implemented persistently in creator.ts. */

  // ------------------------------------------------------------ app updater
  // In-app update mechanism (2026-09-29): the mobile apps poll
  // GET /api/app/version?app=user|creator, compare versionCode with the
  // installed build, and download the APK from /api/app/download.
  // Releases are published via POST /api/admin/app-release (admin secret).

  const VALID_APP_TYPES = new Set(["user", "creator"]);

  function resolveAppType(req: Request): string | null {
    const t = String((req.query as { app?: string }).app || "").toLowerCase();
    return VALID_APP_TYPES.has(t) ? t : null;
  }

  /**
   * Latest release metadata for an app. Public — the client checks this on
   * launch before deciding whether to show the "Update available" banner.
   */
  app.get("/api/app/version", async (req: Request, res: Response) => {
    const appType = resolveAppType(req);
    if (!appType) {
      res.status(400).json({ error: "Query param 'app' must be 'user' or 'creator'." });
      return;
    }
    try {
      const rows = await sql(
        `SELECT version_code, version_name, apk_size_bytes, apk_md5, apk_url, changelog, mandatory, created_at
         FROM app_releases WHERE app_type = $1 ORDER BY version_code DESC LIMIT 1`,
        [appType],
      );
      if (rows.length === 0) {
        res.status(404).json({ error: "No releases published for this app yet." });
        return;
      }
      const r = rows[0] as Record<string, unknown>;
      res.json({
        appType,
        versionCode: r.version_code,
        versionName: r.version_name,
        apkSizeBytes: r.apk_size_bytes,
        apkMd5: r.apk_md5,
        apkUrl: r.apk_url || null,
        changelog: r.changelog,
        mandatory: r.mandatory,
        publishedAt: r.created_at,
        downloadUrl: `/api/app/download?app=${appType}`,
      });
    } catch (err) {
      httpError(res, err, "Could not load release info.");
    }
  });

  /**
   * Download the latest APK for an app. Public — the APK is the app binary
   * itself (destined for the Play Store), not sensitive data. The in-app
   * updater opens this URL in the system browser, which cannot carry the
   * user's auth token.
   */
  app.get("/api/app/download", async (req: Request, res: Response) => {
    const appType = resolveAppType(req);
    if (!appType) {
      res.status(400).json({ error: "Query param 'app' must be 'user' or 'creator'." });
      return;
    }
    try {
      const rows = await sql(
        `SELECT version_name, apk_data, apk_url, apk_size_bytes, apk_md5
         FROM app_releases WHERE app_type = $1 ORDER BY version_code DESC LIMIT 1`,
        [appType],
      );
      if (rows.length === 0) {
        res.status(404).json({ error: "No releases published for this app yet." });
        return;
      }
      const r = rows[0] as Record<string, unknown>;
      // URL-based release: redirect to the hosted APK.
      if (r.apk_url) {
        res.redirect(302, String(r.apk_url));
        return;
      }
      const apk = r.apk_data as Buffer;
      if (!apk) {
        res.status(404).json({ error: "No APK available for this release." });
        return;
      }
      res.setHeader("Content-Type", "application/vnd.android.package-archive");
      res.setHeader(
        "Content-Disposition",
        `attachment; filename="MinuteMate-${appType}-${r.version_name}.apk"`,
      );
      res.setHeader("Content-Length", String(r.apk_size_bytes));
      res.setHeader("X-APK-MD5", String(r.apk_md5));
      res.send(apk);
    } catch (err) {
      httpError(res, err, "Could not download release.");
    }
  });

  /**
   * Publish a new app release (admin only). Body: { adminSecret, appType,
   * versionCode, versionName, apkBase64|apkUrl, apkSizeBytes?, apkMd5?,
   * changelog?, mandatory? }.
   *
   * Two modes:
   * - apkBase64: binary uploaded inline (for small files; Neon HTTP has
   *   payload limits, so large APKs should use apkUrl instead).
   * - apkUrl: direct download URL (e.g. GitHub release asset). Requires
   *   apkSizeBytes and apkMd5 for the client to verify the download.
   */
  const adminJson = express.json({ limit: "32mb" });
  app.post("/api/admin/app-release", adminJson, async (req: Request, res: Response) => {
    const body = (req.body as Record<string, unknown> | undefined) ?? {};
    const adminSecret = process.env.APP_ADMIN_SECRET || "";
    const appType = String(body.appType || "").toLowerCase();
    if (!VALID_APP_TYPES.has(appType)) {
      res.status(400).json({ error: "appType must be 'user' or 'creator'." });
      return;
    }
    // Auth: APP_ADMIN_SECRET must be configured; otherwise reject all
    // publication attempts. (The temporary bootstrap path has been removed
    // for security — releases are seeded only with a valid admin secret.)
    if (!adminSecret) {
      res.status(503).json({ error: "Release publication is not configured." });
      return;
    }
    if (body.adminSecret !== adminSecret) {
      res.status(403).json({ error: "Forbidden." });
      return;
    }
    const versionCode = Number(body.versionCode);
    const versionName = String(body.versionName || "");
    if (!Number.isInteger(versionCode) || versionCode <= 0 || !versionName) {
      res.status(400).json({ error: "versionCode and versionName are required." });
      return;
    }

    // Mode 1: URL-based (preferred for large APKs).
    const apkUrl = String(body.apkUrl || "");
    if (apkUrl) {
      const apkSizeBytes = Number(body.apkSizeBytes);
      const apkMd5 = String(body.apkMd5 || "");
      if (!Number.isInteger(apkSizeBytes) || apkSizeBytes <= 0 || !/^[a-f0-9]{32}$/i.test(apkMd5)) {
        res.status(400).json({ error: "apkUrl mode requires apkSizeBytes and apkMd5." });
        return;
      }
      const id = crypto.randomUUID();
      try {
        await sql(
          `INSERT INTO app_releases
             (id, app_type, version_code, version_name, apk_data, apk_url, apk_size_bytes, apk_md5, changelog, mandatory)
           VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9)`,
          [
            id,
            appType,
            versionCode,
            versionName,
            apkUrl,
            apkSizeBytes,
            apkMd5.toLowerCase(),
            body.changelog ? String(body.changelog) : null,
            body.mandatory === true,
          ],
        );
        res.json({ success: true, id, appType, versionCode, versionName, apkUrl, apkSizeBytes, apkMd5 });
      } catch (err) {
        httpError(res, err, "Could not publish release.");
      }
      return;
    }

    // Mode 2: inline base64 (small files only).
    const apkBase64 = String(body.apkBase64 || "");
    if (!apkBase64) {
      res.status(400).json({ error: "apkBase64 or apkUrl is required." });
      return;
    }
    let apk: Buffer;
    try {
      apk = Buffer.from(apkBase64, "base64");
    } catch {
      res.status(400).json({ error: "apkBase64 is not valid base64." });
      return;
    }
    // Sanity: APK files start with the ZIP magic "PK".
    if (apk.length < 4 || apk[0] !== 0x50 || apk[1] !== 0x4b) {
      res.status(400).json({ error: "Uploaded file is not a valid APK (missing ZIP header)." });
      return;
    }
    const md5 = crypto.createHash("md5").update(apk).digest("hex");
    const id = crypto.randomUUID();
    try {
      await sql(
        `INSERT INTO app_releases
           (id, app_type, version_code, version_name, apk_data, apk_url, apk_size_bytes, apk_md5, changelog, mandatory)
         VALUES ($1, $2, $3, $4, $5, NULL, $6, $7, $8, $9)`,
        [
          id,
          appType,
          versionCode,
          versionName,
          apk,
          apk.length,
          md5,
          body.changelog ? String(body.changelog) : null,
          body.mandatory === true,
        ],
      );
      res.json({
        success: true,
        id,
        appType,
        versionCode,
        versionName,
        apkSizeBytes: apk.length,
        apkMd5: md5,
      });
    } catch (err) {
      httpError(res, err, "Could not publish release.");
    }
  });

  /* ---------------------------------------------------------------- */
  /* Admin dashboard (adminSecret query param auth)                     */
  /* ---------------------------------------------------------------- */

  /**
   * Timing-safe admin secret check for dashboard endpoints.
   * Returns true when authorized; sends 403 and returns false otherwise.
   * The secret itself is never logged.
   */
  function checkDashboardAuth(req: Request, res: Response): boolean {
    const configured = process.env.APP_ADMIN_SECRET || "";
    const provided = String(req.query.adminSecret || "");
    if (!configured) {
      res.status(503).json({ error: "Admin dashboard is not configured." });
      return false;
    }
    const a = Buffer.from(provided);
    const b = Buffer.from(configured);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      res.status(403).json({ error: "Forbidden." });
      return false;
    }
    return true;
  }

  /** Parse a dashboard time-range selector into a "created_at >=" Date, or null for lifetime. */
  function dashboardRangeStart(range: string): Date | null {
    const now = Date.now();
    const ms: Record<string, number> = {
      "1h": 3_600_000,
      "1d": 86_400_000,
      "1w": 7 * 86_400_000,
      "1m": 30 * 86_400_000,
      "1y": 365 * 86_400_000,
    };
    const span = ms[range];
    return span ? new Date(now - span) : null;
  }

  /** Bucket size for report time series. */
  function dashboardBucket(range: string): string {
    if (range === "1h" || range === "1d") return "hour";
    if (range === "1y") return "month";
    return "day";
  }

  /**
   * GET /api/admin/dashboard/stats?adminSecret=XXX&range=1h|1d|1w|1m|1y
   * Overview counts: users, creators, calls, revenue, active calls, pending approvals.
   * With ?range=, also returns period-filtered numbers for the time filter.
   */
  app.get("/api/admin/dashboard/stats", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const [userRow] = await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'user'`;
      const [creatorRow] = await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'creator'`;
      const [callRow] = await sql`SELECT COUNT(*)::int AS c FROM call_sessions`;
      const [revenueRow] = await sql`SELECT COALESCE(SUM(cost_paise), 0)::bigint AS s FROM call_sessions WHERE status = 'ended'`;
      const [activeRow] = await sql`SELECT COUNT(*)::int AS c FROM call_sessions WHERE status IN ('ringing', 'active')`;
      const [pendingRow] = await sql`SELECT COUNT(*)::int AS c FROM creator_profiles WHERE verification_status = 'pending'`;
      const [pendingKycRow] = await sql`SELECT COUNT(*)::int AS c FROM kyc_submissions WHERE status = 'pending'`;
      const payload: Record<string, unknown> = {
        totalUsers: userRow.c,
        totalCreators: creatorRow.c,
        totalCalls: callRow.c,
        totalRevenuePaise: Number(revenueRow.s),
        activeCalls: activeRow.c,
        pendingApprovals: pendingRow.c,
        pendingKyc: pendingKycRow.c,
      };
      const since = dashboardRangeStart(String(req.query.range || ""));
      if (since) {
        const [p] = await sql`
          SELECT COUNT(*)::int AS calls,
                 COALESCE(SUM(cost_paise), 0)::bigint AS revenue,
                 COALESCE(SUM(duration_sec), 0)::bigint AS minutes_x60
          FROM call_sessions WHERE created_at >= ${since}`;
        const [pu] = await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'user' AND created_at >= ${since}`;
        const [pc] = await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'creator' AND created_at >= ${since}`;
        payload.period = {
          range: String(req.query.range),
          calls: p.calls,
          revenuePaise: Number(p.revenue),
          minutes: Math.round(Number(p.minutes_x60) / 60),
          newUsers: pu.c,
          newCreators: pc.c,
        };
      }
      res.json(payload);
    } catch (err) {
      httpError(res, err, "Could not load dashboard stats.");
    }
  });

  /**
   * GET /api/admin/dashboard/users?adminSecret=XXX&limit&offset&search
   * Paginated user list with wallet balance, call counts and spend.
   */
  app.get("/api/admin/dashboard/users", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const search = String(req.query.search || "").trim();
      const like = search ? `%${search}%` : null;

      const countRows = like
        ? await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'user' AND (phone ILIKE ${like} OR COALESCE(name,'') ILIKE ${like} OR COALESCE(display_name,'') ILIKE ${like} OR COALESCE(member_id,'') ILIKE ${like})`
        : await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'user'`;
      const total = countRows[0].c;

      const rows = like
        ? await sql`
            SELECT u.id, u.phone, u.name, u.display_name, u.member_id, u.status, u.created_at,
                   COALESCE(w.balance_paise, 0)::bigint AS balance_paise,
                   (SELECT COUNT(*)::int FROM call_sessions c WHERE c.user_id = u.id) AS total_calls,
                   COALESCE((SELECT SUM(cost_paise)::bigint FROM call_sessions c WHERE c.user_id = u.id AND c.status = 'ended'), 0) AS total_spent_paise
            FROM users u
            LEFT JOIN wallets w ON w.user_id = u.id
            WHERE u.role = 'user' AND (u.phone ILIKE ${like} OR COALESCE(u.name,'') ILIKE ${like} OR COALESCE(u.display_name,'') ILIKE ${like} OR COALESCE(u.member_id,'') ILIKE ${like})
            ORDER BY u.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`
        : await sql`
            SELECT u.id, u.phone, u.name, u.display_name, u.member_id, u.status, u.created_at,
                   COALESCE(w.balance_paise, 0)::bigint AS balance_paise,
                   (SELECT COUNT(*)::int FROM call_sessions c WHERE c.user_id = u.id) AS total_calls,
                   COALESCE((SELECT SUM(cost_paise)::bigint FROM call_sessions c WHERE c.user_id = u.id AND c.status = 'ended'), 0) AS total_spent_paise
            FROM users u
            LEFT JOIN wallets w ON w.user_id = u.id
            WHERE u.role = 'user'
            ORDER BY u.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`;

      res.json({
        total,
        limit,
        offset,
        users: rows.map((r: Record<string, unknown>) => ({
          id: r.id,
          phone: r.phone,
          name: r.name || r.display_name || null,
          memberId: r.member_id || null,
          status: r.status,
          balancePaise: Number(r.balance_paise),
          totalCalls: r.total_calls,
          totalSpentPaise: Number(r.total_spent_paise),
          createdAt: r.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load users.");
    }
  });

  /**
   * GET /api/admin/dashboard/creators?adminSecret=XXX&limit&offset&search
   * Paginated creator list with profile, earnings wallet, call stats, ratings.
   */
  app.get("/api/admin/dashboard/creators", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const search = String(req.query.search || "").trim();
      const like = search ? `%${search}%` : null;

      const countRows = like
        ? await sql`SELECT COUNT(*)::int AS c FROM users u JOIN creator_profiles p ON p.user_id = u.id WHERE u.role = 'creator' AND (u.phone ILIKE ${like} OR p.display_name ILIKE ${like} OR COALESCE(u.member_id,'') ILIKE ${like})`
        : await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'creator'`;
      const total = countRows[0].c;

      const rows = like
        ? await sql`
            SELECT u.id, u.phone, u.member_id, u.status AS user_status, u.created_at,
                   p.display_name, p.price_per_min_paise, p.verification_status, p.kyc_status,
                   p.is_online, p.rating, p.rating_count, p.total_calls, p.total_minutes,
                   COALESCE(cw.balance_paise, 0)::bigint AS earnings_balance_paise,
                   COALESCE(cw.lifetime_paise, 0)::bigint AS lifetime_earnings_paise
            FROM users u
            JOIN creator_profiles p ON p.user_id = u.id
            LEFT JOIN creator_wallets cw ON cw.user_id = u.id
            WHERE u.role = 'creator' AND (u.phone ILIKE ${like} OR p.display_name ILIKE ${like} OR COALESCE(u.member_id,'') ILIKE ${like})
            ORDER BY u.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`
        : await sql`
            SELECT u.id, u.phone, u.member_id, u.status AS user_status, u.created_at,
                   p.display_name, p.price_per_min_paise, p.verification_status, p.kyc_status,
                   p.is_online, p.rating, p.rating_count, p.total_calls, p.total_minutes,
                   COALESCE(cw.balance_paise, 0)::bigint AS earnings_balance_paise,
                   COALESCE(cw.lifetime_paise, 0)::bigint AS lifetime_earnings_paise
            FROM users u
            JOIN creator_profiles p ON p.user_id = u.id
            LEFT JOIN creator_wallets cw ON cw.user_id = u.id
            WHERE u.role = 'creator'
            ORDER BY u.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`;

      res.json({
        total,
        limit,
        offset,
        creators: rows.map((r: Record<string, unknown>) => ({
          id: r.id,
          phone: r.phone,
          memberId: r.member_id || null,
          name: r.display_name,
          ratePaisePerMin: Number(r.price_per_min_paise),
          status: r.user_status,
          verificationStatus: r.verification_status,
          kycStatus: r.kyc_status,
          isOnline: r.is_online,
          rating: r.rating_count ? Number(r.rating) / 10 : null,
          ratingCount: r.rating_count,
          totalCalls: r.total_calls,
          totalMinutes: r.total_minutes,
          earningsBalancePaise: Number(r.earnings_balance_paise),
          lifetimeEarningsPaise: Number(r.lifetime_earnings_paise),
          createdAt: r.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load creators.");
    }
  });

  /**
   * GET /api/admin/dashboard/calls?adminSecret=XXX&limit&offset&status
   * Paginated call sessions with user/creator names.
   * status filter: ringing|active|ended|rejected|missed|cancelled
   */
  app.get("/api/admin/dashboard/calls", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const statusFilter = String(req.query.status || "").trim().toLowerCase();
      const validStatuses = ["ringing", "active", "ended", "rejected", "missed", "cancelled"];
      const status = validStatuses.includes(statusFilter) ? statusFilter : null;

      const countRows = status
        ? await sql`SELECT COUNT(*)::int AS c FROM call_sessions WHERE status = ${status}`
        : await sql`SELECT COUNT(*)::int AS c FROM call_sessions`;
      const total = countRows[0].c;

      const rows = status
        ? await sql`
            SELECT c.id, c.user_id, c.creator_id, c.call_type, c.status, c.duration_sec,
                   c.cost_paise, c.rate_paise_per_min, c.started_at, c.ended_at, c.created_at,
                   COALESCE(uu.display_name, uu.phone) AS user_name,
                   COALESCE(cc.display_name, uu2.phone) AS creator_name
            FROM call_sessions c
            LEFT JOIN users uu ON uu.id = c.user_id
            LEFT JOIN creator_profiles cc ON cc.user_id = c.creator_id
            LEFT JOIN users uu2 ON uu2.id = c.creator_id
            WHERE c.status = ${status}
            ORDER BY c.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`
        : await sql`
            SELECT c.id, c.user_id, c.creator_id, c.call_type, c.status, c.duration_sec,
                   c.cost_paise, c.rate_paise_per_min, c.started_at, c.ended_at, c.created_at,
                   COALESCE(uu.display_name, uu.phone) AS user_name,
                   COALESCE(cc.display_name, uu2.phone) AS creator_name
            FROM call_sessions c
            LEFT JOIN users uu ON uu.id = c.user_id
            LEFT JOIN creator_profiles cc ON cc.user_id = c.creator_id
            LEFT JOIN users uu2 ON uu2.id = c.creator_id
            WHERE TRUE
            ORDER BY c.created_at DESC
            LIMIT ${limit} OFFSET ${offset}`;

      res.json({
        total,
        limit,
        offset,
        calls: rows.map((r: Record<string, unknown>) => ({
          id: r.id,
          userId: r.user_id,
          userName: r.user_name,
          creatorId: r.creator_id,
          creatorName: r.creator_name,
          type: r.call_type,
          status: r.status,
          durationSec: r.duration_sec,
          costPaise: Number(r.cost_paise),
          ratePaisePerMin: Number(r.rate_paise_per_min),
          startedAt: r.started_at,
          endedAt: r.ended_at,
          createdAt: r.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load calls.");
    }
  });

  /**
   * GET /api/admin/dashboard/approvals?adminSecret=XXX&limit&offset
   * Creators waiting for verification approval (verification_status='pending').
   */
  app.get("/api/admin/dashboard/approvals", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);

      const countRows = await sql`SELECT COUNT(*)::int AS c FROM creator_profiles WHERE verification_status = 'pending'`;
      const total = countRows[0].c;

      const rows = await sql`
        SELECT u.id, u.phone, u.member_id, u.created_at,
               p.display_name, p.bio, p.languages, p.price_per_min_paise, p.avatar_url,
               p.allowed_call_types, p.kyc_status, p.talks_about, p.hobbies,
               (SELECT COUNT(*)::int FROM kyc_submissions k WHERE k.user_id = u.id AND k.status = 'pending') AS pending_kyc_docs
        FROM users u
        JOIN creator_profiles p ON p.user_id = u.id
        WHERE p.verification_status = 'pending'
        ORDER BY u.created_at ASC
        LIMIT ${limit} OFFSET ${offset}`;

      res.json({
        total,
        limit,
        offset,
        approvals: rows.map((r: Record<string, unknown>) => ({
          id: r.id,
          phone: r.phone,
          memberId: r.member_id || null,
          name: r.display_name,
          bio: r.bio || null,
          languages: r.languages,
          ratePaisePerMin: Number(r.price_per_min_paise),
          avatarUrl: r.avatar_url || null,
          allowedCallTypes: r.allowed_call_types,
          kycStatus: r.kyc_status,
          talksAbout: r.talks_about,
          hobbies: r.hobbies,
          pendingKycDocs: r.pending_kyc_docs,
          appliedAt: r.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load approvals.");
    }
  });

  /**
   * POST /api/admin/dashboard/creators/:id/decision?adminSecret=XXX
   * Body: { decision: 'approve' | 'reject', note? }
   * Approving sets verification_status='approved'; rejecting sets 'rejected'.
   */
  app.post("/api/admin/dashboard/creators/:id/decision", express.json(), async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const creatorId = String(req.params.id);
      const body = (req.body as Record<string, unknown> | undefined) ?? {};
      const decision = String(body.decision || "").toLowerCase();
      if (decision !== "approve" && decision !== "reject") {
        res.status(400).json({ error: "decision must be 'approve' or 'reject'." });
        return;
      }
      const newStatus = decision === "approve" ? "approved" : "rejected";
      const result = await sql`
        UPDATE creator_profiles
        SET verification_status = ${newStatus}, updated_at = NOW()
        WHERE user_id = ${creatorId}
        RETURNING user_id`;
      if (result.length === 0) {
        res.status(404).json({ error: "Creator profile not found." });
        return;
      }
      res.json({ success: true, creatorId, verificationStatus: newStatus });
    } catch (err) {
      httpError(res, err, "Could not update creator status.");
    }
  });

  /**
   * GET /api/admin/dashboard/kyc?adminSecret=XXX&limit&offset&status
   * KYC document submissions with creator info. status: pending|approved|rejected (default pending).
   */
  app.get("/api/admin/dashboard/kyc", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const limit = Math.min(Math.max(Number(req.query.limit) || 50, 1), 200);
      const offset = Math.max(Number(req.query.offset) || 0, 0);
      const statusFilter = String(req.query.status || "pending").toLowerCase();
      const status = ["pending", "approved", "rejected"].includes(statusFilter) ? statusFilter : "pending";

      const countRows = await sql`SELECT COUNT(*)::int AS c FROM kyc_submissions WHERE status = ${status}`;
      const total = countRows[0].c;

      const rows = await sql`
        SELECT k.id, k.user_id, k.doc_type, k.doc_url, k.status, k.reviewer_note, k.created_at, k.reviewed_at,
               COALESCE(p.display_name, u.phone) AS creator_name, u.phone AS creator_phone,
               p.verification_status AS creator_verification_status
        FROM kyc_submissions k
        JOIN users u ON u.id = k.user_id
        LEFT JOIN creator_profiles p ON p.user_id = k.user_id
        WHERE k.status = ${status}
        ORDER BY k.created_at ASC
        LIMIT ${limit} OFFSET ${offset}`;

      res.json({
        total,
        limit,
        offset,
        status,
        submissions: rows.map((r: Record<string, unknown>) => ({
          id: r.id,
          creatorId: r.user_id,
          creatorName: r.creator_name,
          creatorPhone: r.creator_phone,
          creatorVerificationStatus: r.creator_verification_status,
          docType: r.doc_type,
          docUrl: r.doc_url,
          status: r.status,
          reviewerNote: r.reviewer_note || null,
          submittedAt: r.created_at,
          reviewedAt: r.reviewed_at || null,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load KYC submissions.");
    }
  });

  /**
   * POST /api/admin/dashboard/kyc/:id/decision?adminSecret=XXX
   * Body: { decision: 'approve' | 'reject', note? }
   * Approving also flips the creator's kyc_status to 'verified'; rejecting sets 'rejected'.
   */
  app.post("/api/admin/dashboard/kyc/:id/decision", express.json(), async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const kycId = String(req.params.id);
      const body = (req.body as Record<string, unknown> | undefined) ?? {};
      const decision = String(body.decision || "").toLowerCase();
      if (decision !== "approve" && decision !== "reject") {
        res.status(400).json({ error: "decision must be 'approve' or 'reject'." });
        return;
      }
      const newStatus = decision === "approve" ? "approved" : "rejected";
      const note = typeof body.note === "string" ? body.note.slice(0, 500) : null;
      const result = await sql`
        UPDATE kyc_submissions
        SET status = ${newStatus}, reviewer_note = ${note}, reviewed_at = NOW()
        WHERE id = ${kycId}
        RETURNING user_id`;
      if (result.length === 0) {
        res.status(404).json({ error: "KYC submission not found." });
        return;
      }
      const creatorId = (result[0] as Record<string, unknown>).user_id as string;
      const kycStatus = decision === "approve" ? "verified" : "rejected";
      await sql`UPDATE creator_profiles SET kyc_status = ${kycStatus}, updated_at = NOW() WHERE user_id = ${creatorId}`;
      res.json({ success: true, kycId, status: newStatus, creatorId, creatorKycStatus: kycStatus });
    } catch (err) {
      httpError(res, err, "Could not update KYC status.");
    }
  });

  /**
   * GET /api/admin/dashboard/users/:id?adminSecret=XXX
   * Full user profile: identity, wallet, spend stats, recent calls, recent transactions.
   */
  app.get("/api/admin/dashboard/users/:id", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const userId = String(req.params.id);
      const [u] = await sql`
        SELECT u.id, u.phone, u.name, u.display_name, u.member_id, u.status, u.role,
               u.avatar_url, u.created_at,
               COALESCE(w.balance_paise, 0)::bigint AS balance_paise
        FROM users u
        LEFT JOIN wallets w ON w.user_id = u.id
        WHERE u.id = ${userId}`;
      if (!u) {
        res.status(404).json({ error: "User not found." });
        return;
      }
      const r = u as Record<string, unknown>;
      const [spendRow] = await sql`
        SELECT COUNT(*)::int AS calls, COALESCE(SUM(cost_paise), 0)::bigint AS spent
        FROM call_sessions WHERE user_id = ${userId} AND status = 'ended'`;
      const callRows = await sql`
        SELECT c.id, c.call_type, c.status, c.duration_sec, c.cost_paise, c.created_at,
               COALESCE(p.display_name, u2.phone) AS creator_name
        FROM call_sessions c
        LEFT JOIN creator_profiles p ON p.user_id = c.creator_id
        LEFT JOIN users u2 ON u2.id = c.creator_id
        WHERE c.user_id = ${userId}
        ORDER BY c.created_at DESC LIMIT 25`;
      const txRows = await sql`
        SELECT id, type, amount_paise, bonus_paise, balance_after_paise, description, created_at
        FROM transactions WHERE user_id = ${userId}
        ORDER BY created_at DESC LIMIT 25`;
      const s = spendRow as Record<string, unknown>;
      res.json({
        profile: {
          id: r.id, phone: r.phone, name: r.name || null, displayName: r.display_name || null,
          memberId: r.member_id || null, status: r.status, role: r.role,
          avatarUrl: r.avatar_url || null, joinedAt: r.created_at,
          walletBalancePaise: Number(r.balance_paise),
          totalCalls: s.calls, totalSpentPaise: Number(s.spent),
        },
        calls: (callRows as Record<string, unknown>[]).map((c) => ({
          id: c.id, type: c.call_type, status: c.status,
          durationSec: c.duration_sec, costPaise: Number(c.cost_paise),
          creatorName: c.creator_name, createdAt: c.created_at,
        })),
        transactions: (txRows as Record<string, unknown>[]).map((t) => ({
          id: t.id, type: t.type, amountPaise: Number(t.amount_paise),
          bonusPaise: Number(t.bonus_paise), balanceAfterPaise: Number(t.balance_after_paise),
          description: t.description || null, createdAt: t.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load user profile.");
    }
  });

  /**
   * GET /api/admin/dashboard/creators/:id?adminSecret=XXX
   * Full creator profile: identity, rates, online/call-type status, wallet,
   * bank details, KYC submissions, withdrawals, recent calls.
   */
  app.get("/api/admin/dashboard/creators/:id", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const creatorId = String(req.params.id);
      const [row] = await sql`
        SELECT u.id, u.phone, u.name, u.member_id, u.status AS user_status, u.created_at,
               p.display_name, p.bio, p.languages, p.price_per_min_paise, p.avatar_url,
               p.media_urls, p.intro_video_url, p.allowed_call_types, p.verification_status,
               p.kyc_status, p.is_online, p.random_match_enabled, p.rating, p.rating_count,
               p.total_calls, p.total_minutes, p.talks_about, p.hobbies,
               COALESCE(cw.balance_paise, 0)::bigint AS earnings_balance_paise,
               COALESCE(cw.lifetime_paise, 0)::bigint AS lifetime_earnings_paise,
               b.account_holder, b.account_number, b.ifsc, b.upi_id
        FROM users u
        JOIN creator_profiles p ON p.user_id = u.id
        LEFT JOIN creator_wallets cw ON cw.user_id = u.id
        LEFT JOIN creator_bank_details b ON b.user_id = u.id
        WHERE u.id = ${creatorId}`;
      if (!row) {
        res.status(404).json({ error: "Creator not found." });
        return;
      }
      const r = row as Record<string, unknown>;
      const kycRows = await sql`
        SELECT id, doc_type, doc_url, status, reviewer_note, created_at, reviewed_at
        FROM kyc_submissions WHERE user_id = ${creatorId} ORDER BY created_at DESC`;
      const wdRows = await sql`
        SELECT id, amount_paise, destination, status, created_at, processed_at
        FROM withdrawals WHERE creator_id = ${creatorId} ORDER BY created_at DESC LIMIT 25`;
      const callRows = await sql`
        SELECT c.id, c.call_type, c.status, c.duration_sec, c.cost_paise, c.rate_paise_per_min, c.created_at,
               COALESCE(u2.display_name, u2.phone) AS user_name
        FROM call_sessions c
        LEFT JOIN users u2 ON u2.id = c.user_id
        WHERE c.creator_id = ${creatorId}
        ORDER BY c.created_at DESC LIMIT 25`;
      const rating = Number(r.rating || 0);
      res.json({
        profile: {
          id: r.id, phone: r.phone, realName: r.name || null, memberId: r.member_id || null,
          accountStatus: r.user_status, joinedAt: r.created_at,
          displayName: r.display_name, bio: r.bio || null, languages: r.languages,
          ratePaisePerMin: Number(r.price_per_min_paise),
          avatarUrl: r.avatar_url || null, mediaUrls: r.media_urls, introVideoUrl: r.intro_video_url || null,
          allowedCallTypes: r.allowed_call_types,
          videoCallEnabled: r.allowed_call_types === "video" || r.allowed_call_types === "both",
          audioCallEnabled: r.allowed_call_types === "audio" || r.allowed_call_types === "both",
          verificationStatus: r.verification_status, kycStatus: r.kyc_status,
          isOnline: r.is_online, randomMatchEnabled: r.random_match_enabled,
          rating: rating / 10, ratingCount: r.rating_count,
          totalCalls: r.total_calls, totalMinutes: r.total_minutes,
          talksAbout: r.talks_about, hobbies: r.hobbies,
          earningsBalancePaise: Number(r.earnings_balance_paise),
          lifetimeEarningsPaise: Number(r.lifetime_earnings_paise),
          bankDetails: r.account_number || r.upi_id ? {
            accountHolder: r.account_holder || null,
            accountNumber: r.account_number || null,
            ifsc: r.ifsc || null,
            upiId: r.upi_id || null,
          } : null,
        },
        kyc: (kycRows as Record<string, unknown>[]).map((k) => ({
          id: k.id, docType: k.doc_type, docUrl: k.doc_url, status: k.status,
          reviewerNote: k.reviewer_note || null, submittedAt: k.created_at, reviewedAt: k.reviewed_at || null,
        })),
        withdrawals: (wdRows as Record<string, unknown>[]).map((w) => ({
          id: w.id, amountPaise: Number(w.amount_paise), destination: w.destination,
          status: w.status, createdAt: w.created_at, processedAt: w.processed_at || null,
        })),
        calls: (callRows as Record<string, unknown>[]).map((c) => ({
          id: c.id, type: c.call_type, status: c.status,
          durationSec: c.duration_sec, costPaise: Number(c.cost_paise),
          ratePaisePerMin: Number(c.rate_paise_per_min),
          userName: c.user_name, createdAt: c.created_at,
        })),
      });
    } catch (err) {
      httpError(res, err, "Could not load creator profile.");
    }
  });

  /**
   * GET /api/admin/dashboard/reports/overview?adminSecret=XXX&range=1h|1d|1w|1m|1y
   * Report data: time-series buckets, totals, top creators, top spenders, status breakdown.
   * The dashboard renders charts and generates CSV downloads from this.
   */
  app.get("/api/admin/dashboard/reports/overview", async (req: Request, res: Response) => {
    if (!checkDashboardAuth(req, res)) return;
    try {
      const range = String(req.query.range || "1w");
      const since = dashboardRangeStart(range) || dashboardRangeStart("1w")!;
      const bucket = dashboardBucket(range);

      const callBuckets = await sql`
        SELECT date_trunc(${bucket}, created_at) AS t, COUNT(*)::int AS calls,
               COALESCE(SUM(cost_paise), 0)::bigint AS revenue,
               COALESCE(SUM(duration_sec), 0)::bigint AS secs
        FROM call_sessions WHERE created_at >= ${since}
        GROUP BY 1 ORDER BY 1` as unknown as Record<string, unknown>[];
      const userBuckets = await sql`
        SELECT date_trunc(${bucket}, created_at) AS t, COUNT(*)::int AS c
        FROM users WHERE role = 'user' AND created_at >= ${since}
        GROUP BY 1 ORDER BY 1` as unknown as Record<string, unknown>[];
      const creatorBuckets = await sql`
        SELECT date_trunc(${bucket}, created_at) AS t, COUNT(*)::int AS c
        FROM creator_profiles WHERE created_at >= ${since}
        GROUP BY 1 ORDER BY 1` as unknown as Record<string, unknown>[];

      const bucketMap = new Map<string, { t: string; calls: number; revenuePaise: number; minutes: number; newUsers: number; newCreators: number }>();
      const key = (t: unknown) => new Date(t as string).toISOString();
      for (const b of callBuckets) {
        bucketMap.set(key(b.t), {
          t: key(b.t), calls: b.calls as number, revenuePaise: Number(b.revenue),
          minutes: Math.round(Number(b.secs) / 60), newUsers: 0, newCreators: 0,
        });
      }
      for (const b of userBuckets) {
        const k = key(b.t);
        const e = bucketMap.get(k) || { t: k, calls: 0, revenuePaise: 0, minutes: 0, newUsers: 0, newCreators: 0 };
        e.newUsers = b.c as number;
        bucketMap.set(k, e);
      }
      for (const b of creatorBuckets) {
        const k = key(b.t);
        const e = bucketMap.get(k) || { t: k, calls: 0, revenuePaise: 0, minutes: 0, newUsers: 0, newCreators: 0 };
        e.newCreators = b.c as number;
        bucketMap.set(k, e);
      }
      const buckets = [...bucketMap.values()].sort((a, b) => a.t.localeCompare(b.t));

      const [totals] = await sql`
        SELECT COUNT(*)::int AS calls, COALESCE(SUM(cost_paise), 0)::bigint AS revenue,
               COALESCE(SUM(duration_sec), 0)::bigint AS secs
        FROM call_sessions WHERE created_at >= ${since}` as unknown as Record<string, unknown>[];
      const [tu] = await sql`SELECT COUNT(*)::int AS c FROM users WHERE role = 'user' AND created_at >= ${since}`;
      const [tc] = await sql`SELECT COUNT(*)::int AS c FROM creator_profiles WHERE created_at >= ${since}`;

      const topCreators = await sql`
        SELECT c.creator_id AS id, COALESCE(p.display_name, u.phone) AS name,
               COUNT(*)::int AS calls, COALESCE(SUM(c.duration_sec), 0)::int AS secs,
               COALESCE(SUM(c.cost_paise), 0)::bigint AS revenue
        FROM call_sessions c
        LEFT JOIN creator_profiles p ON p.user_id = c.creator_id
        LEFT JOIN users u ON u.id = c.creator_id
        WHERE c.created_at >= ${since} AND c.status = 'ended'
        GROUP BY c.creator_id, p.display_name, u.phone
        ORDER BY secs DESC LIMIT 10` as unknown as Record<string, unknown>[];

      const topSpenders = await sql`
        SELECT t.user_id AS id, COALESCE(u.display_name, u.name, u.phone) AS name, u.phone,
               COUNT(*)::int AS calls, COALESCE(SUM(-t.amount_paise), 0)::bigint AS spent
        FROM transactions t
        JOIN users u ON u.id = t.user_id
        WHERE t.type = 'call_debit' AND t.created_at >= ${since}
        GROUP BY t.user_id, u.display_name, u.name, u.phone
        ORDER BY spent DESC LIMIT 10` as unknown as Record<string, unknown>[];

      const statusRows = await sql`
        SELECT status, COUNT(*)::int AS c FROM call_sessions
        WHERE created_at >= ${since} GROUP BY status` as unknown as Record<string, unknown>[];

      res.json({
        range,
        bucket,
        buckets,
        totals: {
          calls: (totals as Record<string, unknown>).calls,
          revenuePaise: Number((totals as Record<string, unknown>).revenue),
          minutes: Math.round(Number((totals as Record<string, unknown>).secs) / 60),
          newUsers: (tu as Record<string, unknown>).c,
          newCreators: (tc as Record<string, unknown>).c,
        },
        topCreators: (topCreators as Record<string, unknown>[]).map((x) => ({
          id: x.id, name: x.name, calls: x.calls,
          minutes: Math.round(Number(x.secs) / 60), revenuePaise: Number(x.revenue),
        })),
        topSpenders: (topSpenders as Record<string, unknown>[]).map((x) => ({
          id: x.id, name: x.name, phone: x.phone, calls: x.calls, spentPaise: Number(x.spent),
        })),
        statusBreakdown: (statusRows as Record<string, unknown>[]).map((x) => ({ status: x.status, count: x.c })),
      });
    } catch (err) {
      httpError(res, err, "Could not load report.");
    }
  });
}
