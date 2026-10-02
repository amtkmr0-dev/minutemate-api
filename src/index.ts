/**
 * MinuteMate API — Express application entry point.
 *
 * Boots the HTTP server, registers routes, and applies baseline security
 * headers (helmet) + CORS. The server refuses to boot in production without
 * JWT_SECRET and DATABASE_URL (see auth.ts / db.ts).
 */

import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { registerRoutes } from "./routes.js";
import { registerCreatorRoutes } from "./creator.js";
import { runStartupMigration } from "./migrate.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = Number(process.env.PORT) || 3000;

// Trust Render/Heroku-style proxies so req.ip is correct behind the load balancer.
app.set("trust proxy", 1);

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        // The mobile web client loads Razorpay Checkout from here.
        "script-src": ["'self'", "https://checkout.razorpay.com"],
        "frame-src": ["'self'", "https://api.razorpay.com", "https://checkout.razorpay.com"],
        "connect-src": ["'self'", "https:"],
        "img-src": ["'self'", "data:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(
  cors({
    // Reflect the request origin (including "null" from Capacitor file://
    // WebViews) so CORS preflights succeed. Wildcard "*" cannot be used
    // with credentials:true, and the cors package drops the ACAO header
    // for null origins — both break the Android app's fetch calls.
    origin: (reqOrigin, callback) => {
      callback(null, reqOrigin || "*");
    },
    credentials: true,
  }),
);
app.use(express.json({
  limit: "8mb",
  // 2026-10-02: stash the raw body bytes so the Razorpay webhook can verify
  // the x-razorpay-signature HMAC (it must be computed over the exact bytes
  // Razorpay sent, not re-serialized JSON).
  verify: (req, _res, buf) => {
    (req as unknown as { rawBody?: Buffer }).rawBody = buf;
  },
}));

registerRoutes(app);
registerCreatorRoutes(app);

// 2026-10-02: self-hosted admin dashboard — the same dashboard page, served
// from this backend so it stays up independent of Muse hosting/credits.
// Secret-gated login inside the page; no secret is embedded.
app.get(
  "/admin",
  helmet({
    contentSecurityPolicy: {
      directives: {
        // The dashboard is one self-contained file with inline script/style.
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "connect-src": ["'self'", "https:"],
        "img-src": ["'self'", "data:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
  (_req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "admin.html"));
  },
);

// 2026-10-02: QA preview of the rebuilt dashboard — same page, separate URL
// so the live /admin stays untouched until QA passes. Remove after promotion.
app.get(
  "/admin-qa",
  helmet({
    contentSecurityPolicy: {
      directives: {
        "script-src": ["'self'", "'unsafe-inline'"],
        "style-src": ["'self'", "'unsafe-inline'"],
        "connect-src": ["'self'", "https:"],
        "img-src": ["'self'", "data:", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
  (_req, res) => {
    res.sendFile(path.join(__dirname, "..", "public", "admin-qa.html"));
  },
);

// 404 for unknown API routes — keeps clients from misreading HTML error pages.
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "Not found" });
});

// Last-resort error handler — never leak stack traces to clients.
app.use(
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  (err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error("[unhandled]", err);
    res.status(500).json({ error: "Something went wrong. Please try again." });
  },
);

async function boot(): Promise<void> {
  try {
    await runStartupMigration();
    console.log("[minutemate-api] startup migration complete");
  } catch (err) {
    console.error("[minutemate-api] startup migration FAILED — continuing anyway", err);
  }
  app.listen(PORT, () => {
    console.log(`[minutemate-api] listening on :${PORT} (NODE_ENV=${process.env.NODE_ENV || "development"})`);
  });
}

void boot();
