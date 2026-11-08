import { describe, expect, it } from "vitest";
import { rotateRefreshToken, signRefreshToken } from "../src/auth.js";
import { refreshTokens, users } from "../src/schema.js";
import { seedUser } from "./fixtures/auth.js";
import { db } from "./fixtures/db.js";

describe("refresh token rotation", () => {
  it.each(["banned", "deleted"])("does not refresh an account changed to %s", async (status) => {
    const user = await seedUser();
    const token = await signRefreshToken(user.id);
    await db.update(users).set({ status });
    expect(await rotateRefreshToken(token)).toBeNull();
    expect(await db.select().from(refreshTokens)).toEqual([]);
  });

  it("allows exactly one concurrent rotation of a refresh token", async () => {
    const user = await seedUser();
    const token = await signRefreshToken(user.id);
    const rotations = await Promise.all([rotateRefreshToken(token), rotateRefreshToken(token)]);
    expect(rotations.filter(Boolean)).toHaveLength(1);
    expect(await db.select().from(refreshTokens)).toHaveLength(1);
    expect(await rotateRefreshToken(token)).toBeNull();
    const valid = rotations.find(Boolean)!;
    expect(valid).toMatchObject({ userId: user.id, accessToken: expect.any(String), refreshToken: expect.any(String) });
  });
});
