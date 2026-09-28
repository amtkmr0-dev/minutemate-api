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

function httpError(res: Response, err: unknown, fallback: string): void {
  const status = (err as { statusCode?: number })?.statusCode ?? 500;
  const message = err instanceof Error ? err.message : fallback;
  res.status(status).json({ error: message });
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
  app.get("/api/auth/dev-otp", async (req: Request, res: Response) => {
    const secret = req.query.secret as string;
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

  /** Create a call session (stub) */
  app.post("/api/call/sessions", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { creatorId?: string; callType?: string } | undefined) ?? {};
    const sessionId = `sess_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    // In stub mode, creator is "available" — real implementation would check
    // creator online status and create a proper session record.
    res.json({
      sessionId,
      creatorId: body.creatorId,
      callType: body.callType || "video",
      // Mock rate: ₹46/min (matches test creator)
      pricePerMinute: 46,
      status: "waiting",
      // Stub: session expires in 2 minutes if not joined
      expiresAt: new Date(Date.now() + 2 * 60 * 1000).toISOString(),
    });
  });

  /** Get call session status (stub) */
  app.get("/api/call/sessions/:id", authenticateToken, (req: Request, res: Response) => {
    // Stub: always return "active" — real implementation would check DB
    res.json({
      sessionId: req.params.id,
      status: "active",
      pricePerMinute: 46,
    });
  });

  /** Call heartbeat (stub) */
  app.post("/api/call/sessions/:id/heartbeat", authenticateToken, (_req: Request, res: Response) => {
    res.json({ success: true });
  });

  /** End call session (stub) */
  app.post("/api/call/sessions/:id/end", authenticateToken, (req: Request, res: Response) => {
    res.json({ success: true, sessionId: req.params.id, duration: 0, cost: 0 });
  });

  /**
   * Zego token (stub/dummy).
   * Real implementation: generate token using ZEGO_APP_ID + server secret.
   * For testing, returns a dummy token — video will not actually connect
   * until real Zego credentials are configured.
   */
  app.post("/api/zego/token", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { sessionId?: string } | undefined) ?? {};
    const appId = Number(process.env.ZEGO_APP_ID || "0");
    if (!appId) {
      // Dummy mode: return a placeholder so the UI flow can be tested.
      // The Zego SDK will fail to connect with this, which is expected
      // until real credentials are added.
      res.json({
        appId: 0,
        token: "dummy-zego-token-unconfigured",
        userId: (req as AuthenticatedRequest).userId,
        // Flag so the app can show "video unavailable" instead of crashing
        unconfigured: true,
        message: "Zego not configured. Add ZEGO_APP_ID and ZEGO_SERVER_SECRET to enable video calls.",
      });
      return;
    }
    // TODO: real token generation with zego server SDK
    res.status(501).json({ error: "Zego token generation not implemented" });
  });

  /** Create a chat thread (stub) */
  app.post("/api/chat/threads", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { creatorId?: string } | undefined) ?? {};
    if (!body.creatorId) {
      res.status(400).json({ error: "creatorId required" });
      return;
    }
    const threadId = `thread_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    res.json({
      id: threadId,
      creatorId: body.creatorId,
      createdAt: new Date().toISOString(),
    });
  });

  /** Block a creator (stub) */
  app.post("/api/blocks", authenticateToken, async (req: Request, res: Response) => {
    const body = (req.body as { creatorId?: string } | undefined) ?? {};
    if (!body.creatorId) {
      res.status(400).json({ error: "creatorId required" });
      return;
    }
    // Stub: acknowledge. Real implementation would persist to DB.
    res.json({ success: true, creatorId: body.creatorId, blocked: true });
  });

  /** Unblock a creator (stub) */
  app.delete("/api/blocks/:creatorId", authenticateToken, (req: Request, res: Response) => {
    res.json({ success: true, creatorId: req.params.creatorId, blocked: false });
  });

  /** List blocked creators (stub) */
  app.get("/api/blocks", authenticateToken, (_req: Request, res: Response) => {
    res.json({ blocked: [] });
  });
}
