# Local backend hardening and integration contracts

## Scope

This pass changes only the recovered backend clone on `integrate-minutemate-apps`, based on `041876c85482e5ba877e8ce8cfd499bacb17b698`. It does not deploy, change Render settings, run a production migration, access an existing credential, or send real SMS, payment, payout or call traffic. `render.yaml` is a local configuration change, not evidence of the deployed environment.

## Authentication and SMS

- `GET /api/auth/dev-otp` is removed (API 404), not conditionally enabled. There is no universal OTP and no OTP logging.
- `JWT_SECRET` is now required in **every environment**. The shared development signing secret is removed. Tests supply fresh, test-only signing material without reading `.env`.
- OTPs must match a stored SHA-256 challenge before its five-minute expiration. Attempts are capped at five; increments and consumption are conditional atomic database operations. Concurrent verifiers cannot consume a challenge twice. A conditional upsert also enforces the existing 30-second resend cooldown across concurrent sends.
- Accounts whose `users.status` is not `active` cannot receive sessions or use existing access tokens: HTTP 403, `code: "ACCOUNT_DISABLED"`. Missing accounts are rejected. The schema has no separate deletion timestamp; physical deletion removes refresh rows by foreign key, and a non-active status such as `deleted` is refused.
- JSON refresh/logout transport remains unchanged. `POST /api/auth/refresh` receives `{refreshToken}` and returns `{accessToken,token,refreshToken}`. Rotation atomically consumes the old allowlist row; replay loses with 401. Logout still accepts a JSON refresh token or the older refresh-typed Bearer transport. No cookie protocol was added.
- Consumer OTP login keeps `user.id/phone/name/email` and adds actual `role` and `avatarUrl`. `GET /api/user/me` remains the identity route. Creator login still returns a nullable profile and allows pending applicants into their workspace.
- If an authenticated account lookup fails, the response is 503 with `code: "AUTH_UNAVAILABLE"`, not a false session-expired response.

`POST /api/auth/send-otp` and `/api/auth/creator/send-otp` retain `{phone}` and successful `{success,message}` responses. They add truthful SMS state:

| Condition | Response |
| --- | --- |
| Disabled, missing or malformed provider configuration | 503 `{error,code:"SMS_NOT_CONFIGURED",smsConfigured:false}`; no challenge is created |
| Provider accepts the SMS | 200 `{success:true,message,smsConfigured:true}`; the message says **accepted**, not guaranteed handset delivery |
| HTTP/provider rejection, malformed acknowledgement, network failure or timeout | 503 `{error,code:"SMS_DELIVERY_FAILED",smsConfigured:true}`; invalidate that request's challenge, never return the provider error body |
| Resend cooldown | Existing 429 `{error}` contract |
| Invalid phone | Existing 400 `{error}` contract |

Default `SMS_PROVIDER=disabled`. Optional `SMS_PROVIDER=twilio` uses the Twilio Messages REST endpoint with `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` and `TWILIO_FROM_NUMBER` (E.164). It validates configuration, uses Basic authentication and form encoding, refuses redirects, applies a ten-second timeout, and requires a message SID plus an accepted/queued/sending/sent/delivered acknowledgement. Tests inject the HTTP transport; no real sender was used. Sender provisioning, SMS geography/DLT/compliance, provider account validity and actual delivery remain unverified. Existing admin OTP sending uses the same fail-closed delivery service rather than logging a development code; unrelated admin features were not expanded.

## Payments and call media

- Checked-in Render and example defaults are `PAYMENTS_MODE=razorpay`, `PAYMENTS_SIMULATION_ENABLED=false`.
- Simulation is allowed only with both explicit switches and `NODE_ENV=development` or `test`. Production refuses it even with the former override. A forbidden simulation configuration does not fall through into a real Razorpay order.
- Missing Razorpay configuration: order creation returns 503 `{error,code:"PAYMENTS_NOT_CONFIGURED"}`. Forbidden simulation: 503 `{error,code:"PAYMENTS_SIMULATION_DISABLED"}`. The simulation-success route remains 403 when disabled. No order, wallet credit or provider success is fabricated.
- `POST /api/zego/token` requires `{sessionId}` identifying an actual **call session**, not a room ID. The requester must be a participant. Missing/foreign session: 404; non-active session: 409 `CALL_NOT_ACTIVE`; missing stored room: 409 `CALL_ROOM_UNAVAILABLE`; malformed sessionId: 400.
- Missing/invalid Zego config returns 503 `{error,code:"ZEGO_NOT_CONFIGURED",unconfigured:true}` and **no token**. There is no dummy token or arbitrary-room fallback.
- Configured media retains `{appId,serverUrl,token,userId,roomId,expiresIn}`. The room is taken from the stored session, and the Token04 payload is restricted to that room and requesting identity. `userId` remains `user_<account id>` and `expiresIn` remains 3600.
- Configure positive integer `ZEGO_APP_ID`, a 32-byte ASCII `ZEGO_SERVER_SECRET`, and optionally a valid `wss://` `ZEGO_SERVER_URL`. Explicit invalid URL schemes are refused, not silently rewritten. Token generation/decryption is verified locally with fixture keys; actual SDK/provider connectivity is not verified.

## Creator operations and withdrawals

- Going online requires `verificationStatus="approved"` in the conditional presence update. Otherwise 403 `CREATOR_NOT_APPROVED`; pending/rejected creators can still go offline and use their workspace. Missing profile/offline returns 404 `CREATOR_PROFILE_REQUIRED` rather than a false success.
- Call acceptance still requires the proper creator/agency/admin role and the session's creator identity. The update additionally requires approved creator state and a still-ringing session. Non-approved: 403 `CREATOR_NOT_APPROVED`; a raced/unavailable call: 409 `CALL_NOT_AVAILABLE`. Existing accepted session response fields and unconfirmed media timestamps are preserved.
- `POST /api/creator/withdraw` retains **paise** input `{amount}` and rupee response `{success,id,amount,status:"pending",balance}`. Integer-number strings remain accepted for older clients. Fractional/unsafe amounts are rejected with 400 `INVALID_AMOUNT`; minimum is 50000 paise.
- Add optional `{requestId}`: a UUID generated **once per confirmed withdrawal intent**, reused unchanged with the same amount after an uncertain response. Same creator/key/amount retries return the existing withdrawal with `duplicate:true` and current balance. Key reuse by another creator or for a different amount returns 409 `WITHDRAWAL_REQUEST_CONFLICT`, without exposing that request. Invalid keys return 400 `INVALID_REQUEST_ID`.
- Without `requestId`, older clients retain one new request per call; there is no promise to deduplicate separate legacy requests. New clients should always send a stable key across retries.
- The debit and pending-row insertion are one PostgreSQL data-modifying CTE statement. An insertion failure or unique-key conflict rolls back the entire debit; **do not replace the INSERT with `ON CONFLICT DO NOTHING`**, which could commit a debit with no new request. The existing withdrawal primary key arbitrates concurrent idempotent retries. Insufficient balance causes neither write.
- A payout destination must already exist: a UPI ID or account number plus IFSC. No bank/KYC collection or payout-provider integration is added. A pending reservation is **not** an approved payout or completed bank transfer. Existing masked account display/history and role gates are preserved.

## Both-app chat selection

`GET /api/chat/threads?side=user|creator` is additive:

- `side=user` selects rows where the authenticated account is the consumer, including accounts with creator/agency roles.
- `side=creator` requires a `creator` or `agency` account and selects that account's creator-side rows.
- Invalid, empty, repeated or structured side values return 400; an unauthorized creator side returns 403.
- Omitted `side` preserves the legacy role default: creator/agency → creator side; other roles → user side.
- `otherName` uses the selected side. The existing `{threads}` fields/envelope remain unchanged. User/creator IDs supplied in other query parameters cannot select another account's records. Frontends should send their app target explicitly.

## Verification and deployment boundaries

```sh
npm ci
npm test
npm run typecheck
npm run build
npm audit
```

Use Node 22.12+ for Vitest 5.1. Workers are capped at two. Tests use the real Express handlers through Supertest and an isolated in-memory PostgreSQL engine (PGlite). Fixture DDL is derived from the shipped Drizzle schema. Neon is mocked to throw, inherited service configuration is cleared, `.env` is not loaded, non-loopback HTTP is blocked, and external fetch is disabled except explicit injected provider fixtures. `src/index.ts` and its startup migrations are not executed. The legacy creator sweeper can only see the isolated database; its interval is suppressed by the test app fixture.

No schema migration is needed for these changes: existing OTP/refresh primary keys, call-session fields, creator profiles/wallets, and the `withdrawals.id` primary key are used. Existing production schema/configuration must still be independently verified before rollout. This implementation pass does not approve deployment, test real payments/media, or certify all inherited legacy security. In particular, the pre-existing dependency audit still reports four moderate findings and one high Drizzle ORM identifier-escaping advisory; CORS, admin, legacy money settlement and sensitive-data storage were not broadly rewritten. Independent integration/release review is parent-owned.

### Verified local result

- `npm test`: **114 passed**, 0 failed, 0 skipped, across 11 files.
- `npm run typecheck`: passed for source and tests.
- `npm run build`: passed; the server entry point was not run.
- `git diff --check`: passed.
- `npm audit`: exit 1, unchanged **four moderate and one high** findings. The high runtime finding is `drizzle-orm` (GHSA-gpj5-g38j-94v9); the moderate chain is `drizzle-kit`/`@esbuild-kit`/`esbuild`. Upgrading that inherited stack was not folded into this bounded integration pass.

| Test file | Passing cases |
| --- | ---: |
| `tests/auth-config.test.ts` | 3 |
| `tests/auth-http.test.ts` | 13 |
| `tests/auth.test.ts` | 6 |
| `tests/chat-side.test.ts` | 12 |
| `tests/creator-gates.test.ts` | 8 |
| `tests/payments-gates.test.ts` | 8 |
| `tests/refresh.test.ts` | 3 |
| `tests/sms-http.test.ts` | 18 |
| `tests/sms.test.ts` | 4 |
| `tests/withdrawals.test.ts` | 16 |
| `tests/zego.test.ts` | 23 |

The regression cycles were observed failing before their fixes: universal OTP acceptance, OTP disclosure, expiry boundary, concurrent OTP/refresh consumption, lost attempt increments, non-active accounts, false SMS success, unsafe provider configuration, production simulation, unauthorized/inactive media sessions, missing creator approval, non-atomic withdrawal loss, duplicate withdrawal reservations and wrong chat-side selection. Additional passing cases retain existing successful response envelopes and JSON token transport.

### Changed-file inventory

- `README.md`
- `docs/local-hardening.md`
- `.env.example`
- `package-lock.json`
- `package.json`
- `render.yaml`
- `src/auth.ts`
- `src/creator.ts`
- `src/payments.ts`
- `src/routes.ts`
- `src/sms.ts`
- `src/zego.ts`
- `tests/auth-config.test.ts`
- `tests/auth-http.test.ts`
- `tests/auth.test.ts`
- `tests/chat-side.test.ts`
- `tests/creator-gates.test.ts`
- `tests/fixtures/app.ts`
- `tests/fixtures/auth.ts`
- `tests/fixtures/creator.ts`
- `tests/fixtures/db.ts`
- `tests/payments-gates.test.ts`
- `tests/refresh.test.ts`
- `tests/setup.ts`
- `tests/sms-http.test.ts`
- `tests/sms.test.ts`
- `tests/withdrawals.test.ts`
- `tests/zego.test.ts`
- `tsconfig.tests.json`
- `vitest.config.ts`


