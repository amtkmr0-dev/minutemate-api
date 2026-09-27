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
import { registerRoutes } from "./routes.js";

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
    origin: (process.env.ALLOWED_ORIGINS || "*").split(",").map((s) => s.trim()),
    credentials: true,
  }),
);
app.use(express.json({ limit: "100kb" }));

registerRoutes(app);

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

app.listen(PORT, () => {
  console.log(`[minutemate-api] listening on :${PORT} (NODE_ENV=${process.env.NODE_ENV || "development"})`);
});
