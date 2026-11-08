import { randomBytes } from "node:crypto";
import nock from "nock";
import { afterAll, afterEach, beforeAll, beforeEach, vi } from "vitest";

// Clear inherited service configuration BEFORE any application module loads.
for (const key of Object.keys(process.env)) {
  if (/^(DATABASE_URL|JWT_SECRET|PAYMENTS_|RAZORPAY_|SMS_|TWILIO_|ZEGO_|APP_ADMIN_SECRET)/.test(key)) {
    delete process.env[key];
  }
}
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = randomBytes(48).toString("hex");
process.env.SMS_PROVIDER = "disabled";
process.env.PAYMENTS_MODE = "razorpay";
process.env.PAYMENTS_SIMULATION_ENABLED = "false";

vi.mock("../src/db.js", async () => {
  const fixture = await import("./fixtures/db.js");
  return { db: fixture.db, sql: fixture.sql };
});
vi.mock("@neondatabase/serverless", () => ({
  neon: () => { throw new Error("Neon is forbidden in isolated tests"); },
}));

nock.disableNetConnect();
nock.enableNetConnect(/^(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/);

const fixture = await import("./fixtures/db.js");
beforeAll(() => fixture.initializeDatabase());
beforeEach(async () => {
  await fixture.resetDatabase();
  vi.stubGlobal("fetch", vi.fn(async () => {
    throw new Error("External fetch is forbidden in isolated tests");
  }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  nock.cleanAll();
});
afterAll(async () => {
  await fixture.postgres.close();
  nock.enableNetConnect();
});
