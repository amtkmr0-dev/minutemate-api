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
import { db, sql } from "./db.js";
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
    } catch (err) {
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

  /**
   * TEMPORARY TEST ONLY — credit a user's wallet for integration testing.
   * Guarded by the test secret. DELETE THIS before production launch.
   */
  app.post("/api/test/credit-wallet", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { secret?: unknown; amountPaise?: unknown } | undefined) ?? {};
    if (body.secret !== "mm-test-2026") {
      res.status(403).json({ error: "Forbidden" });
      return;
    }
    const amountPaise = Math.round(Number(body.amountPaise ?? 0));
    if (!Number.isFinite(amountPaise) || amountPaise <= 0 || amountPaise > 1000000) {
      res.status(400).json({ error: "Invalid amount." });
      return;
    }
    try {
      const userId = (req as AuthenticatedRequest).userId;
      await sql(
        `INSERT INTO wallets (user_id, balance_paise, updated_at)
         VALUES ($1, $2, now())
         ON CONFLICT (user_id) DO UPDATE SET balance_paise = wallets.balance_paise + $2, updated_at = now()`,
        [userId, amountPaise],
      );
      res.json({ success: true, creditedPaise: amountPaise });
    } catch (err) {
      httpError(res, err, "Could not credit wallet.");
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
      res.json({ appId, serverUrl: "", token, userId: zegoUserId, roomId, expiresIn: 3600 });
    } catch (err) {
      httpError(res, err, "Could not generate call token.");
    }
  });

  /* Chat threads and blocks are implemented persistently in creator.ts. */
}
