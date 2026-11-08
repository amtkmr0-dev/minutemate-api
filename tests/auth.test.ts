import { describe, expect, it, vi } from "vitest";
import { seedOtp, seedUser } from "./fixtures/auth.js";
import { issueOtp, verifyOtp } from "../src/auth.js";
import { otps, users, wallets } from "../src/schema.js";
import { db, postgres } from "./fixtures/db.js";

const phone = "9000000001";

describe("stored OTP verification", () => {
  it("allows only one concurrent OTP send reservation during the cooldown", async () => {
    const results = await Promise.allSettled([issueOtp(phone), issueOtp(phone)]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    expect(await db.select().from(otps)).toHaveLength(1);
  });

  it("consumes an issued challenge with PostgreSQL microsecond timestamps", async () => {
    const { otp } = await issueOtp(phone);
    await postgres.exec("UPDATE otps SET created_at = '2020-01-01T00:00:00.123456Z'");
    const result = await verifyOtp(phone, otp);
    expect(result).toMatchObject({ ok: true, isNewUser: true });
    expect(await db.select().from(users)).toHaveLength(1);
    expect(await db.select().from(wallets)).toHaveLength(1);
    expect(await verifyOtp(phone, otp)).toMatchObject({ ok: false, status: 400 });
  });

  it("counts concurrent wrong attempts without losing increments", async () => {
    await seedUser();
    const otp = await seedOtp(phone);
    await Promise.all(Array.from({ length: 5 }, () => verifyOtp(phone, "111111")));
    expect(await verifyOtp(phone, otp)).toMatchObject({ ok: false, status: 429 });
  });

  it("allows only one concurrent consumer of a matching challenge", async () => {
    const user = await seedUser();
    const otp = await seedOtp(phone);
    const results = await Promise.all([verifyOtp(phone, otp), verifyOtp(phone, otp)]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results).toContainEqual({ ok: true, userId: user.id, isNewUser: false });
    expect(await db.select().from(otps)).toEqual([]);
  });

  it("rejects a challenge at its exact expiration boundary", async () => {
    const expiresAt = new Date("2030-01-01T00:00:00Z");
    await seedOtp(phone, "684215", { expiresAt });
    vi.spyOn(Date, "now").mockReturnValue(expiresAt.getTime());
    expect(await verifyOtp(phone, "684215")).toMatchObject({ ok: false, status: 400 });
    expect(await db.select().from(users)).toEqual([]);
  });

  it("rejects the former universal test OTP when no challenge exists", async () => {
    const result = await verifyOtp(phone, "123456");
    expect(result).toMatchObject({ ok: false, status: 400 });
    expect(await db.select().from(users)).toEqual([]);
    expect(await db.select().from(wallets)).toEqual([]);
    expect(await db.select().from(otps)).toEqual([]);
  });
});
