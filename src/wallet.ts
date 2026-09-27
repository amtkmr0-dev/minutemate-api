/**
 * MinuteMate API — wallet balance + transaction history.
 *
 * All money is stored in PAISE (integers) in the database. Responses convert
 * to rupees because the mobile client formats balances as ₹.
 */

import { desc, eq } from "drizzle-orm";
import { db } from "./db.js";
import { transactions, wallets } from "./schema.js";

export interface WalletSummary {
  /** Spendable balance in rupees. */
  balance: number;
  /** Balance in paise (exact). */
  balancePaise: number;
}

export async function getWalletSummary(userId: string): Promise<WalletSummary> {
  const rows = await db.select().from(wallets).where(eq(wallets.userId, userId)).limit(1);
  if (!rows[0]) {
    await db.insert(wallets).values({ userId, balancePaise: 0 });
    return { balance: 0, balancePaise: 0 };
  }
  const balancePaise = Number(rows[0].balancePaise);
  return { balance: balancePaise / 100, balancePaise };
}

export interface TransactionView {
  id: string;
  type: string;
  /** Signed amount in rupees (positive = credit, negative = debit). */
  amount: number;
  /** Bonus portion in rupees. */
  bonus: number;
  /** Balance after this transaction, rupees. */
  balanceAfter: number;
  description: string | null;
  createdAt: string;
}

export async function getTransactionHistory(
  userId: string,
  limit = 50,
): Promise<TransactionView[]> {
  const safeLimit = Math.min(Math.max(limit, 1), 100);
  const rows = await db
    .select()
    .from(transactions)
    .where(eq(transactions.userId, userId))
    .orderBy(desc(transactions.createdAt))
    .limit(safeLimit);

  return rows.map((t) => ({
    id: t.id,
    type: t.type,
    amount: Number(t.amountPaise) / 100,
    bonus: Number(t.bonusPaise) / 100,
    balanceAfter: Number(t.balanceAfterPaise) / 100,
    description: t.description,
    createdAt: t.createdAt.toISOString(),
  }));
}
