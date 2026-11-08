import { createDecipheriv, randomBytes } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import request from "supertest";
import { signAccessToken } from "../src/auth.js";
import { seedSession } from "./fixtures/creator.js";
import { seedUser } from "./fixtures/auth.js";
import { createTestApp } from "./fixtures/app.js";
import { db } from "./fixtures/db.js";
import { callSessions } from "../src/schema.js";

const app = createTestApp();
function configureZego() {
  vi.stubEnv("ZEGO_APP_ID", "123456789");
  vi.stubEnv("ZEGO_SERVER_SECRET", randomBytes(16).toString("hex"));
  vi.stubEnv("ZEGO_SERVER_URL", "wss://fixture.zegocloud.com/ws");
}

function tokenFor(userId: string, sessionId: unknown) {
  return request(app).post("/api/zego/token")
    .set("Authorization", `Bearer ${signAccessToken(userId)}`).send({ sessionId });
}

describe("session-bound Zego tokens", () => {
  it.each([undefined, "", 17, {}, []].map((value) => [value]))("requires a non-empty string session identifier (%j)", async (sessionId) => {
    const user = await seedUser();
    const response = await tokenFor(user.id, sessionId);
    expect(response.status).toBe(400);
  });

  it("does not mint a room-unrestricted token for an empty stored room", async () => {
    const { caller, session } = await seedSession();
    configureZego();
    await db.update(callSessions).set({ roomId: "" });
    const response = await tokenFor(caller.id, session.id);
    expect(response.status).toBe(409);
    expect(response.body.token).toBeUndefined();
  });

  it.each(["caller", "creator"])("keeps the configured token contract and server-owned room for the %s", async (side) => {
    const fixture = await seedSession();
    const participant = side === "caller" ? fixture.caller : fixture.creator;
    configureZego();
    const response = await tokenFor(participant.id, fixture.session.id);
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({
      appId: 123456789, serverUrl: "wss://fixture.zegocloud.com/ws", userId: `user_${participant.id}`,
      roomId: fixture.session.roomId, expiresIn: 3600,
    });
    expect(response.body.serverSecret).toBeUndefined();
    expect(response.body.token.startsWith("04")).toBe(true);
    const raw = Buffer.from(response.body.token.slice(2), "base64");
    const ivLength = raw.readUInt16BE(8);
    const iv = raw.subarray(10, 10 + ivLength);
    const encrypted = raw.subarray(12 + ivLength);
    const decipher = createDecipheriv("aes-256-cbc", Buffer.from(process.env.ZEGO_SERVER_SECRET!), iv);
    const info = JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString());
    expect(info.user_id).toBe(`user_${participant.id}`);
    expect(JSON.parse(info.payload)).toEqual({ room_id: fixture.session.roomId, privilege: { 1: 1, 2: 1 }, stream_id_list: null });
    expect(info.expire - info.ctime).toBe(3600);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it.each([
    ["ZEGO_APP_ID", ""], ["ZEGO_APP_ID", "-1"], ["ZEGO_APP_ID", "not-an-id"],
    ["ZEGO_SERVER_SECRET", ""], ["ZEGO_SERVER_SECRET", "short"],
    ["ZEGO_SERVER_SECRET", "é".repeat(32)], ["ZEGO_SERVER_URL", "http://invalid.example/ws"],
  ])("reports unavailable media for invalid %s configuration", async (key, value) => {
    const { caller, session } = await seedSession();
    configureZego();
    vi.stubEnv(key, value);
    const response = await tokenFor(caller.id, session.id);
    expect(response.status).toBe(503);
    expect(response.body).toMatchObject({ code: "ZEGO_NOT_CONFIGURED", unconfigured: true });
    expect(response.body.token).toBeUndefined();
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it.each(["ringing", "ended", "rejected", "missed", "cancelled", "settling"])("does not issue a media token for a %s session", async (status) => {
    const { caller, session } = await seedSession(status);
    configureZego();
    const response = await tokenFor(caller.id, session.id);
    expect(response.status).toBe(409);
    expect(response.body.code).toBe("CALL_NOT_ACTIVE");
    expect(response.body.token).toBeUndefined();
  });

  it("refuses an arbitrary non-existent room even with configured credentials", async () => {
    const user = await seedUser();
    configureZego();
    const response = await tokenFor(user.id, "arbitrary-room");
    expect(response.status).toBe(404);
    expect(response.body.token).toBeUndefined();
  });

  it("does not disclose or authorize another caller's session", async () => {
    const { session } = await seedSession();
    const outsider = await seedUser({ id: "outsider-fixture", phone: "9000000003" });
    configureZego();
    const response = await tokenFor(outsider.id, session.id);
    expect(response.status).toBe(404);
    expect(response.body.token).toBeUndefined();
  });
});
