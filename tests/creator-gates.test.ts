import { describe, expect, it } from "vitest";
import request from "supertest";
import { signAccessToken } from "../src/auth.js";
import { callSessions, creatorProfiles } from "../src/schema.js";
import { seedCreator, seedSession } from "./fixtures/creator.js";
import { seedOtp, seedUser } from "./fixtures/auth.js";
import { db } from "./fixtures/db.js";
import { createTestApp } from "./fixtures/app.js";

const app = createTestApp();
function asUser(userId: string) { return { Authorization: `Bearer ${signAccessToken(userId)}` }; }

describe("creator approval gates", () => {
  it.each(["pending", "rejected"])("cannot accept an existing call with %s approval", async (status) => {
    const { creator, session } = await seedSession("ringing", status);
    const response = await request(app).post(`/api/call/sessions/${session.id}/accept`).set(asUser(creator.id)).send({});
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("CREATOR_NOT_APPROVED");
    const [stored] = await db.select().from(callSessions);
    expect(stored.status).toBe("ringing");
    expect(stored.startedAt).toBeNull();
  });

  it("preserves the approved creator acceptance response", async () => {
    const { creator, session } = await seedSession("ringing");
    const response = await request(app).post(`/api/call/sessions/${session.id}/accept`).set(asUser(creator.id)).send({});
    expect(response.status).toBe(200);
    expect(response.body).toMatchObject({ success: true, sessionId: session.id, id: session.id, roomId: session.roomId, status: "active" });
    expect(typeof response.body.acceptedAt).toBe("string");
    expect(response.body.mediaConfirmedAt).toBeNull();
    expect((await db.select().from(callSessions))[0].status).toBe("active");
  });

  it.each(["pending", "rejected"])("cannot go online with %s approval", async (status) => {
    const { creator } = await seedCreator(status);
    const response = await request(app).post("/api/creator/presence").set(asUser(creator.id)).send({ online: true });
    expect(response.status).toBe(403);
    expect(response.body.code).toBe("CREATOR_NOT_APPROVED");
    expect((await db.select().from(creatorProfiles))[0].isOnline).toBe(false);
  });

  it("cannot claim presence success without a creator profile", async () => {
    const creator = await seedUser({ role: "creator" });
    const response = await request(app).post("/api/creator/presence").set(asUser(creator.id)).send({ online: true });
    expect(response.status).toBe(403);
    expect(await db.select().from(creatorProfiles)).toEqual([]);
  });

  it("allows an approved creator to go online and reads back persisted state", async () => {
    const { creator } = await seedCreator();
    const response = await request(app).post("/api/creator/presence").set(asUser(creator.id)).send({ online: true });
    expect(response.status).toBe(200);
    expect(response.body).toEqual({ success: true, isOnline: true });
    expect((await db.select().from(creatorProfiles))[0].isOnline).toBe(true);
  });

  it("lets a pending creator log in, load their workspace, and go offline", async () => {
    const { creator } = await seedCreator("pending");
    const otp = await seedOtp(creator.phone);
    const login = await request(app).post("/api/auth/creator/verify-otp").send({ phone: creator.phone, otp });
    expect(login.status).toBe(200);
    expect(login.body.profile.approvalStatus).toBe("pending");
    expect(login.body.user.role).toBe("creator");
    const profile = await request(app).get("/api/creator/profile").set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(profile.status).toBe(200);
    expect(profile.body.profile.approvalStatus).toBe("pending");
    const offline = await request(app).post("/api/creator/presence").set(asUser(creator.id)).send({ online: false });
    expect(offline.status).toBe(200);
    expect(offline.body).toEqual({ success: true, isOnline: false });
  });
});
