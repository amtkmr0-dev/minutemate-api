/** Safe SMS failures exposed without provider payloads or credentials. */
export class SmsError extends Error {
  readonly statusCode = 503;
  constructor(readonly code: "SMS_NOT_CONFIGURED" | "SMS_DELIVERY_FAILED", readonly smsConfigured: boolean) {
    super(code === "SMS_NOT_CONFIGURED"
      ? "SMS login is not configured on this server."
      : "The SMS provider could not accept the OTP. Please try again later.");
    this.name = "SmsError";
  }
}

export interface SmsProvider {
  sendOtp(phone: string, otp: string): Promise<void>;
}

/** Explicit opt-in only. The transport can be replaced in isolated tests. */
export function getSmsProvider(env: NodeJS.ProcessEnv = process.env, transport: typeof fetch = globalThis.fetch): SmsProvider | null {
  if (env.SMS_PROVIDER !== "twilio") return null;
  const accountSid = env.TWILIO_ACCOUNT_SID;
  const authToken = env.TWILIO_AUTH_TOKEN;
  const from = env.TWILIO_FROM_NUMBER;
  if (!accountSid || !/^AC[0-9a-f]{32}$/i.test(accountSid)
    || !authToken || !/^[0-9a-f]{32}$/i.test(authToken)
    || !from || !/^\+[1-9]\d{7,14}$/.test(from)) return null;

  return {
    async sendOtp(phone, otp) {
      const response = await transport(`https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`, {
        method: "POST",
        redirect: "error",
        signal: AbortSignal.timeout(10_000),
        headers: {
          Authorization: `Basic ${Buffer.from(`${accountSid}:${authToken}`).toString("base64")}`,
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          To: `+91${phone}`,
          From: from,
          Body: `Your MinuteMate OTP is ${otp}. It expires in 5 minutes. Do not share it.`,
        }),
      });
      if (!response.ok) throw new SmsError("SMS_DELIVERY_FAILED", true);
      const result = await response.json() as { sid?: unknown; status?: unknown } | null;
      if (!result || typeof result.sid !== "string" || !/^(SM|MM)[0-9a-f]{32}$/i.test(result.sid)
        || typeof result.status !== "string" || !["accepted", "queued", "sending", "sent", "delivered"].includes(result.status)) {
        throw new SmsError("SMS_DELIVERY_FAILED", true);
      }
    },
  };
}
