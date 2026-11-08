import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { isSimulationAllowed } from "../src/payments.js";
import { signAccessToken } from "../src/auth.js";
import { pendingOrders, wallets } from "../src/schema.js";
import { seedUser } from "./fixtures/auth.js";
import { db } from "./fixtures/db.js";
import { createTestApp } from "./fixtures/app.js";

const app = createTestApp();

describe("payment simulation safety", () => {
  it("ships opt-in SMS and non-simulation example configuration", () => {
    const env = readFileSync(new URL("../.env.example", import.meta.url), "utf8");
    expect(env).toMatch(/^PAYMENTS_MODE=razorpay$/m);
    expect(env).toMatch(/^PAYMENTS_SIMULATION_ENABLED=false$/m);
    expect(env).toMatch(/^SMS_PROVIDER=disabled$/m);
  });

  it("rejects simulated success in production without crediting a wallet", async () => {
    const user = await seedUser();
    await db.insert(wallets).values({ userId: user.id, balancePaise: 10000 });
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PAYMENTS_MODE", "simulation");
    vi.stubEnv("PAYMENTS_SIMULATION_ENABLED", "true");
    const response = await request(app).post("/api/payments/simulate-success")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`).send({ orderId: "SIM_fixture" });
    expect(response.status).toBe(403);
    expect((await db.select().from(wallets))[0].balancePaise).toBe(10000);
    expect(await db.select().from(pendingOrders)).toEqual([]);
  });

  it("does not accept an invented checkout acknowledgement as payment proof", async () => {
    const user = await seedUser();
    const response = await request(app).post("/api/payments/verify")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`).send({
        razorpay_payment_id: "pay_fixture", razorpay_order_id: "order_fixture", razorpay_signature: "invalid",
      });
    expect(response.status).toBe(400);
    expect(await db.select().from(wallets)).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("does not fall through from forbidden simulation to real order creation", async () => {
    const user = await seedUser();
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PAYMENTS_MODE", "simulation");
    vi.stubEnv("PAYMENTS_SIMULATION_ENABLED", "true");
    const response = await request(app).post("/api/payments/create-order")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`).send({ amount: 500 });
    expect(response.status).toBe(503);
    expect(response.body.code).toBe("PAYMENTS_SIMULATION_DISABLED");
    expect(await db.select().from(pendingOrders)).toEqual([]);
    expect(await db.select().from(wallets)).toEqual([]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("reports missing real-payment configuration without minting an order", async () => {
    const user = await seedUser();
    const response = await request(app).post("/api/payments/create-order")
      .set("Authorization", `Bearer ${signAccessToken(user.id)}`).send({ amount: 500 });
    expect(response.status).toBe(503);
    expect(response.body.code).toBe("PAYMENTS_NOT_CONFIGURED");
    expect(response.body.order_id).toBeUndefined();
    expect(await db.select().from(pendingOrders)).toEqual([]);
  });

  it("does not enable simulation in production even if the old override is present", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv("PAYMENTS_MODE", "simulation");
    vi.stubEnv("PAYMENTS_SIMULATION_ENABLED", "true");
    expect(isSimulationAllowed()).toBe(false);
  });

  it("requires explicit simulation opt-in outside production too", () => {
    vi.stubEnv("NODE_ENV", "development");
    vi.stubEnv("PAYMENTS_MODE", "simulation");
    vi.stubEnv("PAYMENTS_SIMULATION_ENABLED", "false");
    expect(isSimulationAllowed()).toBe(false);
  });

  it("ships real-provider, non-simulation Render defaults", () => {
    const render = readFileSync(new URL("../render.yaml", import.meta.url), "utf8");
    expect(render).toMatch(/key: PAYMENTS_MODE\s+value: razorpay/);
    expect(render).toMatch(/key: PAYMENTS_SIMULATION_ENABLED\s+value: "false"/);
  });
});
