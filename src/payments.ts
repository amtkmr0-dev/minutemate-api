/**
 * MinuteMate API — Razorpay wallet recharge.
 *
 * Money flow (the ONLY real-money flow in the app):
 *
 *   1. Client POSTs { amount } (rupees) to /api/payments/create-order.
 *      The amount is validated against the server-side RECHARGE_PACKS list —
 *      anything else is rejected with 400. A Razorpay order is created via the
 *      Orders API (amount in PAISE, currency INR). The pending order is stored
 *      as orderId -> { userId, packId, amountPaise }: the server is the source
 *      of truth, the client never supplies userId or amount again.
 *   2. Client opens Razorpay Checkout with the returned { order_id, key_id }.
 *   3. On success the client POSTs { razorpay_payment_id, razorpay_order_id,
 *      razorpay_signature } to /api/payments/verify. The server verifies the
 *      HMAC-SHA256 signature, dedupes by payment id, looks up OUR pending
 *      order, then credits principal + bonus EXACTLY ONCE.
 *
 * Secrets: RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET come from process.env at
 * runtime only (never from a file, never logged). Only the PUBLIC key_id is
 * ever returned to the client; the secret NEVER leaves the server.
 */

import { createHmac, randomUUID, timingSafeEqual } from "crypto";
import Razorpay from "razorpay";
import { and, eq, gt } from "drizzle-orm";
import { db } from "./db.js";
import { pendingOrders, processedPayments, transactions, users, wallets } from "./schema.js";

// ---------------------------------------------------------------------------
// Server-authoritative recharge packs (amounts in PAISE, integers).
// The client must never dictate the amount — the server validates the
// requested rupees against this list and uses its own paise figure.
// ---------------------------------------------------------------------------

export interface RechargePack {
  packId: string;
  label: string;
  amountPaise: number;
}

export const RECHARGE_PACKS: RechargePack[] = [
  { packId: "pack_100", label: "₹100", amountPaise: 10000 },
  { packId: "pack_250", label: "₹250", amountPaise: 25000 },
  { packId: "pack_500", label: "₹500", amountPaise: 50000 },
  { packId: "pack_1000", label: "₹1000", amountPaise: 100000 },
  { packId: "pack_2000", label: "₹2000", amountPaise: 200000 },
  { packId: "pack_5000", label: "₹5000", amountPaise: 500000 },
];

/** Bonus tiers (rupee ranges → percentage of the recharge credited as bonus). */
export interface BonusTier {
  minAmount: number; // rupees, inclusive
  maxAmount: number; // rupees, inclusive
  bonusPercentage: number;
}

export const BONUS_TIERS: BonusTier[] = [
  { minAmount: 100, maxAmount: 499, bonusPercentage: 0 },
  { minAmount: 500, maxAmount: 999, bonusPercentage: 5 },
  { minAmount: 1000, maxAmount: 1999, bonusPercentage: 10 },
  { minAmount: 2000, maxAmount: 4999, bonusPercentage: 15 },
  { minAmount: 5000, maxAmount: 10000, bonusPercentage: 20 },
];

/** Bonus in PAISE for a recharge of `amountPaise`. */
export function calculateBonusPaise(amountPaise: number): number {
  const rupees = amountPaise / 100;
  const tier = BONUS_TIERS.find((t) => rupees >= t.minAmount && rupees <= t.maxAmount);
  if (!tier || tier.bonusPercentage <= 0) return 0;
  return Math.floor((amountPaise * tier.bonusPercentage) / 100);
}

// ---------------------------------------------------------------------------
// Mode + configuration
// ---------------------------------------------------------------------------

export type PaymentsMode = "razorpay" | "simulation";

/**
 * PAYMENTS_MODE=simulation lets the whole flow run without real money
 * (SIM_ orders, no Razorpay API calls). NEVER allowed in production unless
 * explicitly enabled — a simulated success must never credit real wallets.
 */
export function getPaymentsMode(): PaymentsMode {
  return (process.env.PAYMENTS_MODE || "razorpay").toLowerCase() === "simulation"
    ? "simulation"
    : "razorpay";
}

export function isSimulationAllowed(): boolean {
  if (getPaymentsMode() !== "simulation") return false;
  if (process.env.NODE_ENV === "production" && process.env.PAYMENTS_SIMULATION_ENABLED !== "true") {
    return false;
  }
  return true;
}

export class PaymentNotConfiguredError extends Error {
  statusCode = 500;
  constructor(message = "Payment is not configured on the server") {
    super(message);
    this.name = "PaymentNotConfiguredError";
  }
}

function getRazorpayClient(): Razorpay {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) {
    throw new PaymentNotConfiguredError(
      "RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET are not set on the server.",
    );
  }
  return new Razorpay({ key_id: keyId, key_secret: keySecret });
}

export function getRazorpayKeyId(): string {
  return process.env.RAZORPAY_KEY_ID || "";
}

// ---------------------------------------------------------------------------
// Step 1 — create order
// ---------------------------------------------------------------------------

export interface CreatedOrder {
  orderId: string;
  packId: string;
  amountPaise: number;
  currency: "INR";
  keyId: string;
  simulated: boolean;
}

const PENDING_ORDER_TTL_MS = 30 * 60 * 1000;

/**
 * Validate the requested rupee amount against RECHARGE_PACKS, create the
 * Razorpay order (or a SIM_ order in simulation mode), and persist the
 * pending order. Throws on invalid amount or Razorpay API failure.
 */
export async function createRechargeOrder(amountRupees: number, userId: string): Promise<CreatedOrder> {
  const amount = typeof amountRupees === "string" ? parseFloat(amountRupees) : amountRupees;
  if (!Number.isFinite(amount)) {
    throw new Error("Enter a valid recharge amount");
  }
  const pack = RECHARGE_PACKS.find((p) => p.amountPaise === Math.round(amount * 100));
  if (!pack) {
    throw new Error("Invalid recharge amount. Please choose one of the available packs.");
  }

  const simulated = isSimulationAllowed();
  let orderId: string;

  if (simulated) {
    orderId = `SIM_${randomUUID().replace(/-/g, "").slice(0, 20)}`;
  } else {
    const razorpay = getRazorpayClient();
    const order = await razorpay.orders.create({
      amount: pack.amountPaise,
      currency: "INR",
      receipt: `mm_${Date.now()}_${userId.slice(0, 8)}`,
      notes: { packId: pack.packId, userId },
    });
    orderId = order.id;
  }

  await db.insert(pendingOrders).values({
    orderId,
    userId,
    packId: pack.packId,
    amountPaise: pack.amountPaise,
    expiresAt: new Date(Date.now() + PENDING_ORDER_TTL_MS),
  });

  return {
    orderId,
    packId: pack.packId,
    amountPaise: pack.amountPaise,
    currency: "INR",
    keyId: getRazorpayKeyId(),
    simulated,
  };
}

// ---------------------------------------------------------------------------
// Step 3 — signature verification + idempotent credit
// ---------------------------------------------------------------------------

/**
 * Verify Razorpay's HMAC-SHA256 signature: hex(HMAC(order_id + "|" +
 * payment_id, key_secret)). Uses timingSafeEqual to avoid timing leaks.
 */
export function verifyRazorpaySignature(args: {
  orderId: string;
  paymentId: string;
  signature: string;
}): boolean {
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!secret) return false;
  const expected = createHmac("sha256", secret)
    .update(`${args.orderId}|${args.paymentId}`, "utf8")
    .digest("hex");
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(args.signature, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

export interface VerifyResult {
  success: boolean;
  duplicate: boolean;
  /** Balance AFTER credit, in rupees. */
  balance: number;
  /** Principal credited, rupees. */
  amount: number;
  /** Bonus credited, rupees. */
  bonus: number;
  /** Total credited (principal + bonus), rupees. */
  total: number;
  transactionId: string;
}

async function getOrCreateWallet(userId: string): Promise<{ balancePaise: number }> {
  const rows = await db.select().from(wallets).where(eq(wallets.userId, userId)).limit(1);
  if (rows[0]) return { balancePaise: Number(rows[0].balancePaise) };
  await db.insert(wallets).values({ userId, balancePaise: 0 });
  return { balancePaise: 0 };
}

async function isPaymentProcessed(paymentId: string): Promise<boolean> {
  const rows = await db
    .select({ id: processedPayments.providerPaymentId })
    .from(processedPayments)
    .where(eq(processedPayments.providerPaymentId, paymentId))
    .limit(1);
  return rows.length > 0;
}

/**
 * Verify a Razorpay payment and credit the wallet EXACTLY ONCE.
 *
 * Guarantees:
 * - Signature is checked FIRST — mismatch means no credit, no mark-paid.
 * - A retried verify for the same payment id returns the same result
 *   (idempotent) instead of double-crediting.
 * - userId + amount come from OUR pending order, never from the client.
 * - Bonus is computed server-side from BONUS_TIERS.
 */
export async function verifyAndCreditPayment(args: {
  authenticatedUserId: string;
  razorpayOrderId: string;
  razorpayPaymentId: string;
  razorpaySignature: string;
}): Promise<VerifyResult> {
  const { authenticatedUserId, razorpayOrderId, razorpayPaymentId, razorpaySignature } = args;

  // 1. Signature check first.
  const signatureOk = verifyRazorpaySignature({
    orderId: razorpayOrderId,
    paymentId: razorpayPaymentId,
    signature: razorpaySignature,
  });
  if (!signatureOk) {
    throw Object.assign(new Error("Payment signature verification failed"), { statusCode: 400 });
  }

  // 2. Idempotency — already processed?
  if (await isPaymentProcessed(razorpayPaymentId)) {
    const wallet = await getOrCreateWallet(authenticatedUserId);
    return {
      success: true,
      duplicate: true,
      balance: wallet.balancePaise / 100,
      amount: 0,
      bonus: 0,
      total: 0,
      transactionId: razorpayPaymentId,
    };
  }

  // 3. Source of truth: OUR pending order.
  const pendingRows = await db
    .select()
    .from(pendingOrders)
    .where(
      and(eq(pendingOrders.orderId, razorpayOrderId), gt(pendingOrders.expiresAt, new Date())),
    )
    .limit(1);
  const pending = pendingRows[0];
  if (!pending) {
    throw Object.assign(new Error("Unknown or expired order"), { statusCode: 400 });
  }
  if (pending.userId !== authenticatedUserId) {
    throw Object.assign(new Error("Order does not belong to this user"), { statusCode: 403 });
  }

  // 4. Credit principal + bonus exactly once.
  const amountPaise = Number(pending.amountPaise);
  const bonusPaise = calculateBonusPaise(amountPaise);
  const totalPaise = amountPaise + bonusPaise;

  const wallet = await getOrCreateWallet(pending.userId);
  const newBalancePaise = wallet.balancePaise + totalPaise;
  await db.update(wallets).set({ balancePaise: newBalancePaise, updatedAt: new Date() }).where(eq(wallets.userId, pending.userId));

  const transactionId = randomUUID();
  await db.insert(transactions).values({
    id: transactionId,
    userId: pending.userId,
    type: "recharge",
    amountPaise: totalPaise,
    bonusPaise,
    balanceAfterPaise: newBalancePaise,
    providerPaymentId: razorpayPaymentId,
    providerOrderId: razorpayOrderId,
    description: `Wallet recharge ${pending.packId.replace("pack_", "₹")}${bonusPaise > 0 ? ` (+₹${bonusPaise / 100} bonus)` : ""}`,
  });

  await db.insert(processedPayments).values({
    providerPaymentId: razorpayPaymentId,
    userId: pending.userId,
    orderId: razorpayOrderId,
    amountPaise: totalPaise,
  });

  // 5. Consume the pending order so it cannot be verified again.
  await db.delete(pendingOrders).where(eq(pendingOrders.orderId, razorpayOrderId));

  return {
    success: true,
    duplicate: false,
    balance: newBalancePaise / 100,
    amount: amountPaise / 100,
    bonus: bonusPaise / 100,
    total: totalPaise / 100,
    transactionId,
  };
}

// ---------------------------------------------------------------------------
// Dev-only simulation: complete a SIM_ order without Razorpay.
// ---------------------------------------------------------------------------

/**
 * Simulate a successful payment for a SIM_ order. Only works when simulation
 * is explicitly allowed (never in production unless enabled) and only for
 * orders created in simulation mode.
 */
export async function simulateSuccessfulPayment(args: {
  authenticatedUserId: string;
  orderId: string;
}): Promise<VerifyResult> {
  if (!isSimulationAllowed()) {
    throw Object.assign(
      new Error("Payment simulation is not enabled on this server"),
      { statusCode: 403 },
    );
  }
  if (!args.orderId.startsWith("SIM_")) {
    throw Object.assign(new Error("Only simulation orders can be simulated"), { statusCode: 400 });
  }

  const pendingRows = await db
    .select()
    .from(pendingOrders)
    .where(
      and(eq(pendingOrders.orderId, args.orderId), gt(pendingOrders.expiresAt, new Date())),
    )
    .limit(1);
  const pending = pendingRows[0];
  if (!pending) {
    throw Object.assign(new Error("Unknown or expired order"), { statusCode: 400 });
  }
  if (pending.userId !== args.authenticatedUserId) {
    throw Object.assign(new Error("Order does not belong to this user"), { statusCode: 403 });
  }

  // Mint a synthetic payment id and run the same idempotent credit path.
  const syntheticPaymentId = `SIM_PAY_${randomUUID().replace(/-/g, "").slice(0, 16)}`;
  const amountPaise = Number(pending.amountPaise);
  const bonusPaise = calculateBonusPaise(amountPaise);
  const totalPaise = amountPaise + bonusPaise;

  const wallet = await getOrCreateWallet(pending.userId);
  const newBalancePaise = wallet.balancePaise + totalPaise;
  await db.update(wallets).set({ balancePaise: newBalancePaise, updatedAt: new Date() }).where(eq(wallets.userId, pending.userId));

  const transactionId = randomUUID();
  await db.insert(transactions).values({
    id: transactionId,
    userId: pending.userId,
    type: "recharge",
    amountPaise: totalPaise,
    bonusPaise,
    balanceAfterPaise: newBalancePaise,
    providerPaymentId: syntheticPaymentId,
    providerOrderId: pending.orderId,
    description: `Wallet recharge (simulated) ${pending.packId.replace("pack_", "₹")}${bonusPaise > 0 ? ` (+₹${bonusPaise / 100} bonus)` : ""}`,
  });

  await db.insert(processedPayments).values({
    providerPaymentId: syntheticPaymentId,
    userId: pending.userId,
    orderId: pending.orderId,
    amountPaise: totalPaise,
  });

  await db.delete(pendingOrders).where(eq(pendingOrders.orderId, pending.orderId));

  return {
    success: true,
    duplicate: false,
    balance: newBalancePaise / 100,
    amount: amountPaise / 100,
    bonus: bonusPaise / 100,
    total: totalPaise / 100,
    transactionId,
  };
}

/** Read-only user lookup for response shaping. */
export async function getUserById(userId: string) {
  const rows = await db.select().from(users).where(eq(users.id, userId)).limit(1);
  return rows[0] ?? null;
}
