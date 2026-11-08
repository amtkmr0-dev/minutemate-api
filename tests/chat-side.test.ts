import { describe, expect, it } from "vitest";
import request from "supertest";
import { signAccessToken } from "../src/auth.js";
import { chatMessages, chatThreads, creatorProfiles } from "../src/schema.js";
import { db } from "./fixtures/db.js";
import { seedUser } from "./fixtures/auth.js";
import { createTestApp } from "./fixtures/app.js";

const app = createTestApp();
async function chatFixture(role = "creator") {
  const dual = await seedUser({ id: "dual-account", role, name: "Dual account" });
  const peer = await seedUser({ id: "peer-creator", phone: "9000000002", role: "creator", name: "Peer" });
  const caller = await seedUser({ id: "caller-account", phone: "9000000003", name: "Fixture caller" });
  const outsider = await seedUser({ id: "outsider-account", phone: "9000000004", name: "Not visible" });
  await db.insert(creatorProfiles).values([
    { userId: dual.id, displayName: "Dual public name" },
    { userId: peer.id, displayName: "Peer public name" },
  ]);
  await db.insert(chatThreads).values([
    { id: "own-user-thread", userId: dual.id, creatorId: peer.id },
    { id: "own-creator-thread", userId: caller.id, creatorId: dual.id },
    { id: "unrelated-thread", userId: outsider.id, creatorId: peer.id },
  ]);
  await db.insert(chatMessages).values({
    id: "fixture-message", threadId: "own-user-thread", senderId: dual.id,
    senderRole: "user", body: "Fixture message only",
  });
  return { dual, peer, caller, outsider };
}

function threads(userId: string, query = "") {
  return request(app).get(`/api/chat/threads${query}`).set("Authorization", `Bearer ${signAccessToken(userId)}`);
}

describe("two-app chat side", () => {
  it.each(["?side=invalid", "?side=", "?side=user&side=creator", "?side[]=user"])("rejects invalid side selection %s", async (query) => {
    const { dual } = await chatFixture();
    const response = await threads(dual.id, query);
    expect(response.status).toBe(400);
    expect(response.body.threads).toBeUndefined();
  });

  it.each(["user", "admin"])("does not permit explicit creator-side access for role %s", async (role) => {
    const { dual } = await chatFixture(role);
    const response = await threads(dual.id, "?side=creator");
    expect(response.status).toBe(403);
    expect(response.body.threads).toBeUndefined();
  });

  it.each(["creator", "agency"])("allows explicit creator-side access for role %s without another creator's records", async (role) => {
    const { dual, caller, outsider } = await chatFixture(role);
    const response = await threads(dual.id, `?side=creator&creatorId=${outsider.id}`);
    expect(response.status).toBe(200);
    expect(response.body.threads.map((thread: { id: string }) => thread.id)).toEqual(["own-creator-thread"]);
    expect(response.body.threads[0].otherName).toBe(caller.name);
    expect(JSON.stringify(response.body).includes(outsider.id)).toBe(false);
  });

  it("lets a creator see their own consumer-side conversations with side=user", async () => {
    const { dual, peer, outsider } = await chatFixture();
    const response = await threads(dual.id, `?side=user&userId=${outsider.id}`);
    expect(response.status).toBe(200);
    expect(response.body.threads.map((thread: { id: string }) => thread.id)).toEqual(["own-user-thread"]);
    expect(response.body.threads[0]).toMatchObject({
      creatorId: peer.id, userId: dual.id, otherName: "Peer public name", lastMessage: "Fixture message only",
    });
    expect(JSON.stringify(response.body).includes(outsider.id)).toBe(false);
  });

  it.each(["creator", "agency"])("preserves the omitted-side %s default", async (role) => {
    const { dual, caller } = await chatFixture(role);
    const response = await threads(dual.id);
    expect(response.status).toBe(200);
    expect(response.body.threads.map((thread: { id: string }) => thread.id)).toEqual(["own-creator-thread"]);
    expect(response.body.threads[0].otherName).toBe(caller.name);
  });

  it("preserves the omitted-side consumer default", async () => {
    const { dual } = await chatFixture("user");
    const response = await threads(dual.id);
    expect(response.status).toBe(200);
    expect(response.body.threads.map((thread: { id: string }) => thread.id)).toEqual(["own-user-thread"]);
    expect(response.body.threads[0].otherName).toBe("Peer public name");
  });
});
