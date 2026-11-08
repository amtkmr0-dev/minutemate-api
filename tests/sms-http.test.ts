import { describe, expect, it, vi } from "vitest";
import { createHash, randomBytes } from "node:crypto";
import request from "supertest";
import { otps } from "../src/schema.js";
import { db } from "./fixtures/db.js";
import { createTestApp } from "./fixtures/app.js";
import { seedUser } from "./fixtures/auth.js";

const app = createTestApp();
const paths = ["/api/auth/send-otp", "/api/auth/creator/send-otp"];

function configureSms() {
  vi.stubEnv("SMS_PROVIDER", "twilio");
  vi.stubEnv("TWILIO_ACCOUNT_SID", `AC${"1".repeat(32)}`);
  vi.stubEnv("TWILIO_AUTH_TOKEN", randomBytes(16).toString("hex"));
  vi.stubEnv("TWILIO_FROM_NUMBER", "+15005550006");
}

describe("truthful OTP delivery", () => {
  it.each(["admin", "user"])("does not retain a dev SMS path for a %s account", async (role) => {
    const user = await seedUser({ role });
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const response = await request(app).post("/api/auth/admin/request-otp").send({ mobile: user.phone });
    expect(response.status).toBe(503);
    expect(response.body).toMatchObject({ code: "SMS_NOT_CONFIGURED", smsConfigured: false });
    expect(await db.select().from(otps)).toEqual([]);
    expect(log).not.toHaveBeenCalled();
  });

  it.each(paths.flatMap((path) => ["http-error", "invalid-json", "empty-object", "failed", "missing-sid", "network-error"].map((failure) => [path, failure])))
    ("%s fails honestly and invalidates its challenge on %s", async (path, failure) => {
      configureSms();
      const transport = vi.mocked(globalThis.fetch);
      if (failure === "network-error") transport.mockRejectedValue(new Error("private-provider-diagnostic"));
      else transport.mockResolvedValue(new Response(
        failure === "invalid-json" ? "not-json" : JSON.stringify(
          failure === "empty-object" ? {} : {
            sid: failure === "missing-sid" ? undefined : `SM${"2".repeat(32)}`,
            status: failure === "failed" ? "failed" : "queued",
            message: "private-provider-diagnostic",
          }), { status: failure === "http-error" ? 401 : 201 }));
      const response = await request(app).post(path).send({ phone: "9000000001" });
      expect(response.status).toBe(503);
      expect(response.body).toMatchObject({ code: "SMS_DELIVERY_FAILED", smsConfigured: true });
      expect(response.body.success).not.toBe(true);
      expect(JSON.stringify(response.body).includes("private-provider-diagnostic")).toBe(false);
      expect(await db.select().from(otps)).toEqual([]);
    });

  it.each(paths)("%s only acknowledges an OTP actually accepted by the configured provider", async (path) => {
    configureSms();
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const transport = vi.mocked(globalThis.fetch).mockResolvedValue(new Response(JSON.stringify({
      sid: `SM${"2".repeat(32)}`, status: "queued",
    }), { status: 201 }));
    const response = await request(app).post(path).send({ phone: "+91 90000 00001" });
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ success: true, smsConfigured: true, message: expect.any(String) });
    expect(response.body.otp).toBeUndefined();
    expect(transport).toHaveBeenCalledTimes(1);
    const [url, options] = transport.mock.calls[0];
    expect(url).toBe(`https://api.twilio.com/2010-04-01/Accounts/AC${"1".repeat(32)}/Messages.json`);
    expect(options?.method).toBe("POST");
    const body = new URLSearchParams(String(options?.body));
    expect(body.get("To")).toBe("+919000000001");
    expect(body.get("From")).toBe("+15005550006");
    const otp = body.get("Body")?.match(/\b\d{6}\b/)?.[0];
    expect(Boolean(otp)).toBe(true);
    const [challenge] = await db.select().from(otps);
    expect(challenge.otpHash === createHash("sha256").update(otp!).digest("hex")).toBe(true);
    expect(log).not.toHaveBeenCalled();
    const verify = await request(app).post(path.replace("send-otp", "verify-otp"))
      .send({ phone: "9000000001", otp });
    expect(verify.status).toBe(200);
    expect(verify.body.success).toBe(true);
  });

  it.each(paths)("%s fails closed when SMS is not configured", async (path) => {
    // Prevent the inherited logger from exposing even fixture OTPs on RED.
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const response = await request(app).post(path).send({ phone: "9000000001" });
    expect(response.status).toBe(503);
    expect(response.body).toMatchObject({ code: "SMS_NOT_CONFIGURED", smsConfigured: false });
    expect(response.body.success).not.toBe(true);
    expect(await db.select().from(otps)).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(log).not.toHaveBeenCalled();
  });
});
