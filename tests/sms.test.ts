import { randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { getSmsProvider } from "../src/sms.js";

function config(): NodeJS.ProcessEnv {
  return {
    SMS_PROVIDER: "twilio", TWILIO_ACCOUNT_SID: `AC${"1".repeat(32)}`,
    TWILIO_AUTH_TOKEN: randomBytes(16).toString("hex"), TWILIO_FROM_NUMBER: "+15005550006",
  };
}

describe("Twilio HTTP adapter", () => {
  it.each([
    ["TWILIO_ACCOUNT_SID", "invalid/account"],
    ["TWILIO_AUTH_TOKEN", "   "],
    ["TWILIO_FROM_NUMBER", "not-e164"],
  ])("does not configure an invalid %s", (key, value) => {
    expect(getSmsProvider({ ...config(), [key]: value }) === null).toBe(true);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("bounds the request timeout and refuses credential-bearing redirects", async () => {
    const env = config();
    const timeout = vi.spyOn(AbortSignal, "timeout");
    const transport = vi.mocked(globalThis.fetch).mockResolvedValue(new Response(JSON.stringify({
      sid: `SM${"2".repeat(32)}`, status: "accepted",
    }), { status: 201 }));
    await getSmsProvider(env)!.sendOtp("9000000001", "684215");
    const [, options] = transport.mock.calls[0];
    expect(options?.redirect).toBe("error");
    expect(options?.signal instanceof AbortSignal).toBe(true);
    expect(timeout).toHaveBeenCalledWith(10_000);
    const expected = `Basic ${Buffer.from(`${env.TWILIO_ACCOUNT_SID}:${env.TWILIO_AUTH_TOKEN}`).toString("base64")}`;
    expect(new Headers(options?.headers).get("Authorization") === expected).toBe(true);
    expect(new Headers(options?.headers).get("Content-Type")).toBe("application/x-www-form-urlencoded");
  });
});
