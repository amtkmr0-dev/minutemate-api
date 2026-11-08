import express from "express";
import { vi } from "vitest";
import { registerRoutes } from "../../src/routes.js";
import { registerCreatorRoutes } from "../../src/creator.js";

export function createTestApp() {
  const app = express();
  app.use(express.json({
    verify(req, _res, buffer) {
      (req as unknown as { rawBody: Buffer }).rawBody = buffer;
    },
  }));
  registerRoutes(app);
  // The legacy route registrar starts a sweeper. Prevent its interval from
  // escaping the test; its initial query can only reach our in-memory database.
  const interval = vi.spyOn(globalThis, "setInterval").mockImplementation(() => ({
    unref() {},
  }) as unknown as NodeJS.Timeout);
  registerCreatorRoutes(app);
  interval.mockRestore();
  app.use("/api", (_req, res) => res.status(404).json({ error: "Not found" }));
  return app;
}
