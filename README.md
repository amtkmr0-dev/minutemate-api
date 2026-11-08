# MinuteMate API

Clean standalone backend for the MinuteMate user app — OTP login, Razorpay
wallet recharge, and wallet ledger. Node.js + Express + TypeScript + Drizzle
ORM + Neon Postgres.

## Local verification

Use Node 22.12+ and run the isolated suite before configuring any service:

```bash
npm ci
npm test
npm run typecheck
npm run build
```

Tests do not load `.env`, connect to Neon, run startup migrations or call SMS,
payment or media providers. See [local hardening and integration contracts](docs/local-hardening.md)
for fixture isolation, response/error changes, both-app chat selection, pending
withdrawal idempotency, configuration and remaining deployment blockers.

## Server setup (only with an authorized database and services)

```bash
npm install
cp .env.example .env        # then fill in DATABASE_URL + JWT_SECRET
npm run db:push             # create tables in Neon
npm run dev                 # http://localhost:3000
```

## Environment variables

| Key | Required | Notes |
|---|---|---|
| `DATABASE_URL` | prod | Neon Postgres connection string |
| `JWT_SECRET` | all environments | Long random signing secret; no shared development fallback |
| `PORT` | no | Defaults to 3000 |
| `ALLOWED_ORIGINS` | no | Comma-separated, or `*` for dev |
| `RAZORPAY_KEY_ID` | for real payments | Public key id — returned to the client |
| `RAZORPAY_KEY_SECRET` | for real payments | **Server only.** Never sent to the client |
| `PAYMENTS_MODE` | no | `razorpay` (default) or `simulation` |
| `PAYMENTS_SIMULATION_ENABLED` | no | Explicit `true` only with a disposable database and `NODE_ENV=development`/`test`; never production |
| `SMS_PROVIDER` | no | `disabled` by default; optional `twilio` |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER` | for SMS | Server-only credentials and an E.164 sender; no OTP logging |
| `ZEGO_APP_ID`, `ZEGO_SERVER_SECRET` | for calls | Positive integer AppID and 32-byte ASCII server secret |
| `ZEGO_SERVER_URL` | no | Valid `wss://` endpoint; otherwise the existing AppID-derived default |

## API

### Auth (OTP, Indian mobile)

- `POST /api/auth/send-otp` — `{ "phone": "9876543210" }`
  → `{"success":true,"message":"OTP accepted by SMS provider. Delivery may take a moment.","smsConfigured":true}`
  → `400 {"error":"Invalid phone number"}` for anything that isn't a valid
  10-digit Indian mobile (accepts `+91`/`91`/`0` prefixes and spaces).
  Unconfigured SMS returns 503 `SMS_NOT_CONFIGURED` with `smsConfigured:false`.
  Provider refusal/failure returns 503 `SMS_DELIVERY_FAILED`. No test OTP or
  disclosure route exists, and codes are never logged.
- `POST /api/auth/verify-otp` — `{ "phone": "...", "otp": "<received SMS code>" }`
  → `{ accessToken, token, refreshToken, user }`. Creates the user + wallet
  on first login.
- `POST /api/auth/refresh` — `{ "refreshToken": "..." }` → fresh pair (rotates).
- `POST /api/auth/logout` — `{ "refreshToken": "..." }` → revokes it.

Authenticated routes use `Authorization: Bearer <accessToken>` (15-minute TTL).

### Payments (Razorpay)

- `GET /api/payments/packs` — server-side pack list + bonus tiers for the UI.
- `POST /api/payments/create-order` (auth) — `{ "amount": 500 }`
  → `{ order_id, amount (paise), currency, key_id, simulated? }`.
  Amount is validated against the server-side pack list; anything else → 400.
- `POST /api/payments/verify` (auth) —
  `{ razorpay_payment_id, razorpay_order_id, razorpay_signature }`
  → `{ success, duplicate?, balance, amount, bonus, total, transactionId }`.
  Signature is verified with HMAC-SHA256 + `timingSafeEqual`; payment ids are
  deduped so the wallet is credited **exactly once**; userId + amount come
  from the server's pending order, never the client.
- `POST /api/payments/simulate-success` (auth) — `{ "orderId": "SIM_..." }`.
  Only when both simulation switches are explicitly enabled in development/test
  with a disposable database. Production never permits simulation.

### Wallet

- `GET /api/wallet/me` (auth) → `{ balance, balancePaise }` (balance in ₹).
  `GET /api/wallet` is an alias.
- `GET /api/wallet/me/transactions?limit=50` (auth) → `{ transactions: [...] }`.
  `GET /api/wallet/transactions` is an alias.

### Health

- `GET /api/health` → `{ "status": "ok" }`

## Money rules

- All money is stored in **paise as integers** — never floats.
- The client never dictates amounts: `/create-order` validates against
  `RECHARGE_PACKS`; `/verify` reads userId + amount from the pending order.
- Bonuses are computed server-side from `BONUS_TIERS` (5–20% by pack size).
- `RAZORPAY_KEY_SECRET` never leaves the server.

## Deploy (Render)

`render.yaml` is included: build `npm install && npm run build`, start
`node dist/index.js`. Set `DATABASE_URL`, `RAZORPAY_KEY_ID`, and
`RAZORPAY_KEY_SECRET` in the Render dashboard (never commit them).
Run `npm run db:push` once against the Neon URL to create the tables.
