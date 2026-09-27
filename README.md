# MinuteMate API

Clean standalone backend for the MinuteMate user app — OTP login, Razorpay
wallet recharge, and wallet ledger. Node.js + Express + TypeScript + Drizzle
ORM + Neon Postgres.

## Quick start

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
| `JWT_SECRET` | prod | Long random string (`openssl rand -base64 64`) |
| `PORT` | no | Defaults to 3000 |
| `ALLOWED_ORIGINS` | no | Comma-separated, or `*` for dev |
| `RAZORPAY_KEY_ID` | for real payments | Public key id — returned to the client |
| `RAZORPAY_KEY_SECRET` | for real payments | **Server only.** Never sent to the client |
| `PAYMENTS_MODE` | no | `razorpay` (default) or `simulation` |
| `PAYMENTS_SIMULATION_ENABLED` | no | Must be `true` for simulation in production |

## API

### Auth (OTP, Indian mobile)

- `POST /api/auth/send-otp` — `{ "phone": "9876543210" }`
  → `{"success":true,"message":"OTP sent successfully"}`
  → `400 {"error":"Invalid phone number"}` for anything that isn't a valid
  10-digit Indian mobile (accepts `+91`/`91`/`0` prefixes and spaces).
  In dev the OTP is logged to the console; in production wire up your SMS
  provider in `routes.ts` (`send-otp` handler).
- `POST /api/auth/verify-otp` — `{ "phone": "...", "otp": "123456" }`
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
  Only when `PAYMENTS_MODE=simulation` (never in production unless explicitly
  enabled). For testing the full flow with zero real charges.

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
