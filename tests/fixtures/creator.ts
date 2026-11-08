import { callSessions, creatorProfiles, creatorWallets, wallets } from "../../src/schema.js";
import { db } from "./db.js";
import { seedUser } from "./auth.js";

export async function seedCreator(verificationStatus = "approved") {
  const creator = await seedUser({ id: "creator-fixture", phone: "9000000002", role: "creator", name: "Fixture creator" });
  const [profile] = await db.insert(creatorProfiles).values({
    userId: creator.id, displayName: creator.name!, verificationStatus, isOnline: false,
    pricePerMinPaise: 3000,
  }).returning();
  await db.insert(creatorWallets).values({ userId: creator.id, balancePaise: 100_000, lifetimePaise: 100_000 });
  return { creator, profile };
}

export async function seedSession(status = "active", verificationStatus = "approved") {
  const caller = await seedUser();
  await db.insert(wallets).values({ userId: caller.id, balancePaise: 20_000 });
  const { creator, profile } = await seedCreator(verificationStatus);
  const [session] = await db.insert(callSessions).values({
    id: "session-fixture", userId: caller.id, creatorId: creator.id, roomId: "room_fixture_authoritative",
    status, startedAt: status === "active" ? new Date() : null, ratePaisePerMin: 3000,
  }).returning();
  return { caller, creator, profile, session };
}
