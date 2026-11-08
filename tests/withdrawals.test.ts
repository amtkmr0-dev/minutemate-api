import { describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import request from "supertest";
import { signAccessToken } from "../src/auth.js";
import { creatorBankDetails, creatorWallets, withdrawals } from "../src/schema.js";
import { seedCreator } from "./fixtures/creator.js";
import { seedUser } from "./fixtures/auth.js";
import { db, postgres } from "./fixtures/db.js";
import { createTestApp } from "./fixtures/app.js";

const app = createTestApp();
async function payoutFixture() {
  const { creator } = await seedCreator();
  await db.insert(creatorBankDetails).values({
    userId: creator.id, accountNumber: "000000123456", ifsc: "TEST0000001", accountHolder: "Fixture only",
  });
  return creator;
}
function withdraw(userId: string, body: Record<string, unknown> = { amount: 50000 }) {
  return request(app).post("/api/creator/withdraw")
    .set("Authorization", `Bearer ${signAccessToken(userId)}`).send(body);
}

describe("pending withdrawal reservation", () => {
  it.each([50000.5, "50000.5", [50000], Number.MAX_SAFE_INTEGER + 1].map((value) => [value]))
    ("rejects non-integer or unsafe paise amount %j without a debit", async (amount) => {
      const creator = await payoutFixture();
      const response = await withdraw(creator.id, { amount });
      expect(response.status).toBe(400);
      expect(response.body.code).toBe("INVALID_AMOUNT");
      expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(100000);
      expect(await db.select().from(withdrawals)).toEqual([]);
    });

  it("does not queue a request for incomplete stored bank details", async () => {
    const creator = await payoutFixture();
    await db.update(creatorBankDetails).set({ ifsc: null });
    expect((await withdraw(creator.id)).status).toBe(400);
    expect(await db.select().from(withdrawals)).toEqual([]);
    expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(100000);
  });

  it("never over-reserves when different requests compete for the same earnings", async () => {
    const creator = await payoutFixture();
    const responses = await Promise.all(Array.from({ length: 3 }, () => withdraw(creator.id, { amount: 50000, requestId: randomUUID() })));
    expect(responses.filter((response) => response.status === 200)).toHaveLength(2);
    const rows = await db.select().from(withdrawals);
    expect(rows).toHaveLength(2);
    expect(rows.reduce((sum, row) => sum + row.amountPaise, 0)).toBe(100000);
    expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(0);
  });

  it.each(["not-a-uuid", "", {}, 17].map((value) => [value]))("rejects malformed requestId %j without a debit", async (requestId) => {
    const creator = await payoutFixture();
    const response = await withdraw(creator.id, { amount: 50000, requestId });
    expect(response.status).toBe(400);
    expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(100000);
    expect(await db.select().from(withdrawals)).toEqual([]);
  });

  it("rejects reuse of a requestId with a changed amount", async () => {
    const creator = await payoutFixture();
    const requestId = randomUUID();
    expect((await withdraw(creator.id, { amount: 50000, requestId })).status).toBe(200);
    const response = await withdraw(creator.id, { amount: 60000, requestId });
    expect(response.status).toBe(409);
    expect(response.body.code).toBe("WITHDRAWAL_REQUEST_CONFLICT");
    expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(50000);
  });

  it("does not return another creator's withdrawal for a colliding requestId", async () => {
    const creator = await payoutFixture();
    const requestId = randomUUID();
    expect((await withdraw(creator.id, { amount: 50000, requestId })).status).toBe(200);
    const other = await seedUser({ id: "other-creator", phone: "9000000003", role: "creator" });
    await db.insert(creatorWallets).values({ userId: other.id, balancePaise: 100000 });
    await db.insert(creatorBankDetails).values({ userId: other.id, accountNumber: "000000654321", ifsc: "TEST0000001" });
    const response = await withdraw(other.id, { amount: 50000, requestId });
    expect(response.status).toBe(409);
    expect(response.body.id).toBeUndefined();
    expect(response.body.amount).toBeUndefined();
    expect(await db.select().from(withdrawals)).toHaveLength(1);
  });

  it("keeps the existing paise request and rupee pending-response contract", async () => {
    const creator = await payoutFixture();
    const response = await withdraw(creator.id);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ success: true, amount: 500, status: "pending", balance: 500 });
    const [stored] = await db.select().from(withdrawals);
    expect(stored).toMatchObject({ id: response.body.id, creatorId: creator.id, amountPaise: 50000, status: "pending" });
    expect(stored.destination).toBe("A/C ••3456 TEST0000001");
    expect(stored.processedAt).toBeNull();
  });

  it.each([false, true])("does not reserve twice for a reused requestId (concurrent=%s)", async (concurrent) => {
    const creator = await payoutFixture();
    const body = { amount: 50000, requestId: randomUUID() };
    const responses = concurrent
      ? await Promise.all([withdraw(creator.id, body), withdraw(creator.id, body)])
      : [await withdraw(creator.id, body), await withdraw(creator.id, body)];
    expect(responses.map((r) => r.status)).toEqual([200, 200]);
    expect(responses[0].body.id).toBe(responses[1].body.id);
    expect(await db.select().from(withdrawals)).toHaveLength(1);
    expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(50000);
  });

  it("does not lose earnings if creating the withdrawal row fails", async () => {
    const creator = await payoutFixture();
    await postgres.exec("ALTER TABLE withdrawals ADD CONSTRAINT fixture_reject CHECK (false)");
    try {
      const response = await withdraw(creator.id);
      expect(response.status).toBeGreaterThanOrEqual(500);
      expect((await db.select().from(creatorWallets))[0].balancePaise).toBe(100000);
      expect(await db.select().from(withdrawals)).toEqual([]);
    } finally {
      await postgres.exec("ALTER TABLE withdrawals DROP CONSTRAINT fixture_reject");
    }
  });
});
