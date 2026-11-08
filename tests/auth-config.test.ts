import { describe, expect, it, vi } from "vitest";
import { db, sql } from "./fixtures/db.js";
import config from "../vitest.config.js";

describe("authentication configuration", () => {
  it("disables Vite environment-file loading before the isolation setup", () => {
    expect((config as { envDir?: unknown }).envDir).toBe(false);
  });

  it.each(["development", "production"])("requires an explicit signing secret in %s", async (nodeEnv) => {
    vi.stubEnv("NODE_ENV", nodeEnv);
    vi.stubEnv("JWT_SECRET", "");
    vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.resetModules();
    // Retain the existing isolated engine across a fresh auth-module import.
    vi.doMock("../src/db.js", () => ({ db, sql }));
    const failedClosed = await import("../src/auth.js").then(() => false, () => true);
    expect(failedClosed).toBe(true);
  });
});
