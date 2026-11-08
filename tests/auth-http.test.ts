import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { otps, refreshTokens } from "../src/schema.js";
import { seedOtp, seedUser } from "./fixtures/auth.js";
import { db } from "./fixtures/db.js";
import { createTestApp } from "./fixtures/app.js";
import { signAccessToken } from "../src/auth.js";

const app = createTestApp();

describe("session response contracts", () => {
  it("keeps JSON refresh rotation and logout compatible without cookies", async () => {
    const user = await seedUser();
    const otp = await seedOtp(user.phone);
    const login = await request(app).post("/api/auth/verify-otp").send({ phone: user.phone, otp });
    expect(login.status).toBe(200);
    const oldRefresh = login.body.refreshToken;
    const refresh = await request(app).post("/api/auth/refresh").send({ refreshToken: oldRefresh });
    expect(refresh.status).toBe(200);
    expect(refresh.body.accessToken === refresh.body.token).toBe(true);
    expect(refresh.body.refreshToken !== oldRefresh).toBe(true);
    expect((await request(app).post("/api/auth/refresh").send({ refreshToken: oldRefresh })).status).toBe(401);
    const me = await request(app).get("/api/user/me").set("Authorization", `Bearer ${refresh.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.user.id).toBe(user.id);
    const logout = await request(app).post("/api/auth/logout").send({ refreshToken: refresh.body.refreshToken });
    expect(logout.status).toBe(200);
    expect(logout.body.success).toBe(true);
    expect(await db.select().from(refreshTokens)).toEqual([]);
    expect((await request(app).post("/api/auth/refresh").send({ refreshToken: refresh.body.refreshToken })).status).toBe(401);
  });

  it.each(["user", "creator", "agency"])("preserves identity fields and reports the actual %s role on consumer login", async (role) => {
    const user = await seedUser({ role, email: "fixture@example.invalid", avatarUrl: null });
    const otp = await seedOtp(user.phone);
    const response = await request(app).post("/api/auth/verify-otp").send({ phone: user.phone, otp });
    expect(response.status).toBe(200);
    expect(response.body.user).toEqual({ id: user.id, phone: user.phone, name: user.name, email: user.email, role, avatarUrl: null });
    expect(typeof response.body.accessToken).toBe("string");
    expect(response.body.token === response.body.accessToken).toBe(true);
    expect(typeof response.body.refreshToken).toBe("string");
  });

  it("does not misreport a database outage as an expired session", async () => {
    const user = await seedUser();
    vi.spyOn(db, "select").mockImplementationOnce(() => { throw new Error("private-database-diagnostic"); });
    const response = await request(app).get("/api/user/me")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`);
    expect(response.status).toBe(503);
    expect(response.body.code).toBe("AUTH_UNAVAILABLE");
    expect(JSON.stringify(response.body).includes("private-database-diagnostic")).toBe(false);
  });
});

describe("disabled accounts", () => {
  it.each(["banned", "deleted"])("refuses an existing access token after the account becomes %s", async (status) => {
    const user = await seedUser({ status });
    const response = await request(app).get("/api/user/me")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`);
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("ACCOUNT_DISABLED");
  });

  it("rejects an access token whose account no longer exists", async () => {
    const response = await request(app).get("/api/user/me")
      .set("Authorization", `Bearer ${signAccessToken("removed-account")}`);
    expect(response.status).toBe(401);
  });

  it.each([
    ["/api/auth/verify-otp", "user", "banned"],
    ["/api/auth/creator/verify-otp", "creator", "banned"],
    ["/api/auth/verify-otp", "user", "deleted"],
    ["/api/auth/creator/verify-otp", "creator", "deleted"],
  ])("refuses %s for a %s with status %s before issuing tokens", async (path, role, status) => {
    const user = await seedUser({ role, status });
    const otp = await seedOtp(user.phone);
    const response = await request(app).post(path).send({ phone: user.phone, otp });
    expect(response.status).toBe(403);
    expect(response.body).toMatchObject({ code: "ACCOUNT_DISABLED" });
    expect(response.body.accessToken).toBeUndefined();
    expect(response.body.refreshToken).toBeUndefined();
    expect(await db.select().from(refreshTokens)).toEqual([]);
  });
});

describe("removed test authentication", () => {
  it("does not register the OTP disclosure route even with its former public secret", async () => {
    const response = await request(app).get("/api/auth/dev-otp")
      .query({ secret: "mm-test-2026", phone: "9000000001" });
    expect(response.status).toBe(404);
    expect(response.body).toEqual({ error: "Not found" });
    expect(await db.select().from(otps)).toEqual([]);
  });
});
