import { createHash } from "node:crypto";
import { otps, users } from "../../src/schema.js";
import { db } from "./db.js";

export async function seedUser(overrides: Partial<typeof users.$inferInsert> = {}) {
  const [user] = await db.insert(users).values({
    id: "user-fixture", phone: "9000000001", name: "Fixture user", ...overrides,
  }).returning();
  return user;
}

export async function seedOtp(phone: string, otp = "684215", overrides: Partial<typeof otps.$inferInsert> = {}) {
  await db.insert(otps).values({
    phone,
    otpHash: createHash("sha256").update(otp).digest("hex"),
    expiresAt: new Date(Date.now() + 300_000),
    createdAt: new Date(Date.now() - 31_000),
    attempts: 0,
    ...overrides,
  });
  return otp;
}
