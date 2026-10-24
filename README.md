# User Service

## Overview

`user-service` is the app backend service responsible for identity,
authentication, profile management, session lifecycle, two-factor
authentication, password recovery, and KYC verification orchestration.

It exposes both HTTP and gRPC interfaces and also publishes asynchronous events
and notification requests to RabbitMQ.

## What the service owns

- user records and user numbers
- contacts and contact verification
- profiles and profile updates
- password credentials and password change history
- access sessions, refresh flows, revocation, and auth logs
- two-factor activation, confirmation, deactivation, and challenge resend
- password recovery flows
- verification/KYC lifecycle and webhook processing
- user lifecycle and verification-level update events, delivered through the
  transactional outbox

## Repository map

| Path | Purpose |
| --- | --- |
| `cmd/user-service` | Main runtime entrypoint, startup orchestration, graceful shutdown. |
| `cmd/user-service/app` | Composition root: wires DB, cache, queue, HTTP client, transports, and `Core`. |
| `cmd/commands/migrate` | Standalone migration command. |
| `config` | Env-driven runtime configuration for app, DB, HTTP, gRPC, queue, logger, tracer, cache, and KYC provider settings. |
| `data/db/migrations/postgres` | PostgreSQL schema migrations. |
| `data/geoip` | Local MaxMind databases used for country, timezone, and anonymous/VPN checks. |
| `internal/domain` | Domain entities, enums, DTOs, contracts, queue types, and service interfaces. |
| `internal/domain/errors` | Service-specific error templates and frontend-oriented error contract notes. |
| `internal/controllers` | Use-case orchestration for auth, sessions, registration, password recovery, 2FA, geo, and verification. |
| `internal/controllers/kyc-providers` | Provider-specific verification controllers. |
| `internal/infrastructure/db/postgres` | PostgreSQL repositories. |
| `internal/infrastructure/security/passwords` | Password hashing helpers. |
| `internal/infrastructure/security/sessions` | JWT access-token and refresh-token session helpers. |
| `internal/transport/http` | Gin handlers, auth/session middleware, request validation, Swagger annotations. |
| `internal/transport/grpc` | gRPC service implementation and generated protobuf bindings. |
| `services/geo` | GeoIP/anonymous-IP service backed by local MaxMind databases. |
| `services/kyc/amlbot` | AMLBot verification provider integration. |
| `services/recaptcha` | reCAPTCHA verification integrations. |
| `tools` | Metrics helpers and transport tooling. |
| `docs` | Generated Swagger/OpenAPI artifacts. |

## Runtime architecture

### Composition root

`cmd/user-service/app` is the runtime assembly layer.

`Application.SetupDependencies()` initializes:

1. PostgreSQL connection
2. DB transaction manager
3. RabbitMQ connections
4. Ristretto global local cache
5. Hazelcast remote cache
6. remote cache manager
7. shared outbound HTTP client

`Application.SetupStartupData()` initializes:

1. Prometheus metrics registration
2. queue manager and publishers
3. `Core` with repositories, controllers, caches, security, and service clients
4. HTTP server
5. gRPC server
6. cron manager

### Shutdown happens in two phases

`stopServing` takes down the HTTP and gRPC servers first — that is what lets the
background loops finish, since their goroutines only return once the servers are
down. Then `g.Wait()`. Only after that does `Application.Close` release the
queue, the database pool and the caches.

The order matters more than the closing does. Publishers used to be closed
before `g.Wait()`, while the outbox pool could still be delivering through them.

`Close` is registered with `defer` before setup begins, so a failure partway
through `SetupDependencies` still gives back whatever had been acquired; it
tolerates a half-built `Application` for that reason.

`user-service` registers no queue consumers. Its cron manager hosts the outbox
maintenance jobs (`outbox.prune`, `outbox.lag`) from `common/outbox/cronjobs`
and the service's own retention sweep (`user.cleanup`).

### Retention

Until `user.cleanup` existed the outbox was the only table anything ever deleted
from. `revoked_sessions` was the worst of the rest: a row per logout, per admin
kick and per refresh, which with a fifteen-minute access token is roughly 35,000
rows a year for one active user.

| Table | Deleted when | Default | Setting |
|---|---|---|---|
| `sessions` | both the access and refresh windows have closed | 24h grace | `CRON_SESSION_RETENTION` |
| `revoked_sessions` | older than the refresh token TTL plus grace | 840h (35d) | `CRON_REVOKED_SESSION_RETENTION` |
| `two_factor_tokens` | expired longer ago than the grace | 48h | `CRON_TWO_FACTOR_TOKEN_RETENTION` |

`CRON_REVOKED_SESSION_RETENTION` is not a free number. Those rows carry the hash
of the refresh token the session held, and that hash is the only thing
`detectRefreshTokenReuse` can compare a replayed token against. Pruning by
`expire_at` instead — which tracks the fifteen-minute access token — would delete
the evidence within the hour and leave reuse detection quietly answering
"unknown session" to every replay. A config test fails if the retention drops
below the 30-day refresh TTL.

`auth_logs` and `password_change_logs` are deliberately left alone. They are the
audit trail, and how long a regulated platform keeps one is a compliance
decision rather than an engineering default — but they do grow without bound
today, so the decision is still owed.

### The shared outbound HTTP client is set up once and never mutated

One `req.Client` is built in `setupHTTPClient` and handed to every outbound
service — AMLBot, reCAPTCHA, restriction-service. Sharing it means it must not
be mutated afterwards. Each call used to begin with
`client.SetTimeout(...)`, which writes `httpClient.Timeout`; `net/http` reads
that field on every in-flight request, so two concurrent calls were an
unsynchronised write against a read. `go test -race` reports it as
`req.(*Client).SetTimeout` against `net/http.(*Client).do`.

Per-call bounds come from the request context instead, through
`commonHTTP.WithCallTimeout(ctx, config.Commons().TimeoutExtCall)`, which leaves
the client untouched. A non-positive duration means "no per-call bound", the
same thing `SetTimeout(0)` meant. The client-level timeout from
`setupHTTPClient` stays as the backstop.

This matches how `account-service` uses the same shared client.

### Core structure

`Core` wires together:

- controllers: `UserCtrl`, `AuthCtrl`, `PasswordRecoveryCtrl`, `SessionCtrl`, `OTPCtrl`, `TwoFactorCtrl`, `GeoCtrl`, `UserEventCtrl`, `VerificationCtrl`
- the outbox runtime: one relay goroutine claiming due `outbox_messages` rows plus
  `CRON_OUTBOX_POOL_WORKERS` delivery goroutines, registered in the errgroup in
  `cmd/user-service/main.go`
- repositories for users, contacts, profiles, credentials, password change logs, sessions, revoked sessions, auth logs, two-factor tokens, two-factor settings, and verifications
- cache repository for revoked sessions
- security helpers for password hashing and JWT session handling
- HTTP services for GeoIP, AMLBot, restriction, and reCAPTCHA v3
- outgoing gRPC client for `restriction-service`

### Main architectural layers

- `internal/domain` owns business types, contracts, enums, queue abstractions, and helper constructors.
- `internal/controllers` orchestrate registration, auth, sessions, password recovery, 2FA, verification, and event publication.
- `internal/infrastructure/db/postgres` persists state and maps SQL rows to domain models.
- `internal/infrastructure/security/*` owns password and session helpers.
- `internal/transport/*` translates HTTP and gRPC traffic into controller calls.
- `services/*` owns service-specific external integrations that are local to this repository.

## Transactional outbox

The two user lifecycle events go out through `outbox_messages`, the shared
transactional outbox from `common/outbox`.

| `event_type` | Written by | Delivered to | Idempotency downstream |
|---|---|---|---|
| `user.created` | `UserCtrl.VerifyContact` | user lifecycle queue | `restriction-service` upserts the tier (`CreateOrUpdateUserTier`) |
| `user.verify_level.updated` | `VerificationCtrl.Process`, only on a passed verification | user lifecycle queue | same upsert |

Both used to be published after the commit with the error logged and dropped.
Losing `user.created` left a user activated here while `restriction-service` never
learned they existed and never assigned a tier; losing
`user.verify_level.updated` meant a user passed KYC while their limits stayed at
the unverified tier. Neither left any trace that it should have happened.

Invariants when touching this:

- write the row **inside** the business transaction, before `Commit`, and return
  the error rather than logging it. A logged-and-swallowed enqueue failure is the
  exact defect the outbox exists to remove.
- the verification dedupe key carries the **level**:
  `verify-level:{userID}:{level}`. A user moves 1 → 2 → 3 and each step is its own
  event; keying on the user alone would make the second promotion look like a
  duplicate of the first and drop it, leaving their limits one tier behind.
- `user-created:{userID}` needs no such discriminator — a user is created once.
- delivery is at-least-once and unordered. Adding a new event type means proving
  its consumer tolerates both, the way `CreateOrUpdateUserTier` already does.
- a payload that cannot decode must return `outbox.MarkNonRetryable`; transport
  failures stay retryable.
- keep `CRON_OUTBOX_*` defaults aligned with the other adopting services. They are
  not independent tuning knobs — divergent values mean the shared dashboard and
  alert rules stop describing every service.

The `outbox_messages` DDL is **not** in `data/db/migrations/postgres`. It is
applied from the embedded FS in `common/outbox/postgres/migrations`, which
`cmd/commands/migrate` runs as a second source against its own history table,
`schema_migrations_outbox`. Use `-source=service|outbox|all` to aim a command at
one of them.

Design, tuning, and failure modes live in `common/outbox/README.md` and
`ARCHITECTURE.md`. Do not re-document them here.

### OTP is deliberately not on the outbox

The OTP token lives five minutes. A durable retry would deliver an expired code,
or a second live one after the user already pressed resend. The failure that
mattered was different: the send error was logged while the API returned success,
so the user waited for a code that was never coming.

Every OTP send now surfaces its failure to the caller — **except**
`UserCtrl.Register`. There the user and their verification token are already
committed, and returning an error would discard the `TokenUUID` the client needs
for the resend endpoint while the contact-already-used guard blocks
re-registering. The caller would be left with an account they can never verify.

Registration therefore still returns `200` with the token, and reports the
delivery outcome instead:

- the response carries `codeDelivered`. When it is `false` the account exists and
  the token is valid, but nothing was sent — prompt for a resend rather than
  telling the user to check an inbox that will stay empty.
- `dispatched_at` is cleared on a failed send. It is stamped when the token is
  created, before the send is attempted, so leaving it would run the resend
  cooldown against a dispatch that never happened and answer the first resend
  with a 429.

Resend goes through the existing public endpoint:

```
POST /api/v1/2fa/otp/resend   {"tokenUUID": "...", "tokenType": "verify_contact"}
```

It is unauthenticated, keyed on the token UUID alone, IP rate limited at the
route, and additionally throttled per token by `OTP_REFRESH_INTERVAL` (default
1m) — that throttle answers with `CodeResendRateLimitedError` and a `retryAfter`
timestamp.

## Interfaces and integrations

### HTTP API

The HTTP API is mounted under `/api/v1`.

Public auth endpoints:

- `POST /api/v1/auth/login`
- `POST /api/v1/auth/login/challenge/confirm`

Protected auth/session endpoints:

- `GET /api/v1/auth/me`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/logout-all`
- `GET /api/v1/auth/sessions`
- `DELETE /api/v1/auth/sessions/:sessionId`
- `POST /api/v1/auth/sessions/refresh`

Important note:

- refresh is not an anonymous endpoint
- it uses the session middleware in "skip expired access-token validation" mode
- it also requires a `refreshToken` in the request body

Public user endpoints:

- `POST /api/v1/users/register`
- `POST /api/v1/users/verify-contact`
- `POST /api/v1/users/password/forgot`
- `POST /api/v1/users/password/reset/confirm`

Protected user endpoints:

- `GET /api/v1/users/get-profile`
- `PATCH /api/v1/users/update-profile`
- `POST /api/v1/users/password-change`

Two-factor endpoints:

- `POST /api/v1/2fa/otp/resend`
- `POST /api/v1/2fa/activate`
- `POST /api/v1/2fa/deactivate`
- `POST /api/v1/2fa/confirm`
- `GET /api/v1/2fa/settings`
- `POST /api/v1/2fa/challenge/resend`

Verification endpoints:

- `POST /api/v1/verifications/init`
- `POST /api/v1/verifications/aml-bot/webhook`

Internal security-token protected endpoints:

- `DELETE /api/v1/internal/sessions/:sessionId`
- `POST /api/v1/internal/sessions/validate`
- `POST /api/v1/internal/users/block`
- `POST /api/v1/internal/users/events`

Operational endpoints:

- `GET /api/v1/health`
- `GET /api/v1/swagger/*any`

Public HTTP endpoints are rate-limited individually in `http_server.go`.

### gRPC API

The gRPC contract is defined in `proto/user/v1/user.proto`.

Current RPCs:

- `GetProfile`
- `GetUserByNumber`
- `ValidateSession`

The service implementation lives in `internal/transport/grpc/user`, while the
generated bindings live in `internal/transport/grpc/pb/userv1`.

### Queue integrations

RabbitMQ publishers configured by the service:

- OTP notification dispatch
- push notification dispatch (the exchange stays declared, but nothing in this
  service publishes to it — the push controller was dead wiring and is gone)
- user lifecycle events, published by the outbox worker rather than directly

Published user lifecycle routing keys currently include:

- `user.created`
- `user.verify_level.updated`

`user-service` currently does not configure RabbitMQ consumers.

### External dependencies

The service depends on:

- PostgreSQL for persistent state
- RabbitMQ for OTP and user-event publishing
- Hazelcast plus Ristretto for revoked-session cache storage
- `restriction-service` over HTTP and gRPC
- AMLBot over HTTP for KYC initialization and webhook-driven verification updates
- Google reCAPTCHA v3 over HTTP
- local MaxMind GeoIP databases under `data/geoip`
- `common` for logging, tracing, cache, queue, error handling, middleware, and shared service contracts

## Security, session, and verification model

- Access sessions are JWT-based.
- Refresh tokens are opaque random tokens. Only their SHA-256 is stored, so a
  leaked dump of `sessions` yields hashes rather than working 30-day
  credentials. The raw token exists in the response that issued it and in the
  client holding it, nowhere else.
- Refreshing rotates: the old session row is deleted and a new one issued. The
  revoked row keeps the old hash, which is what makes reuse detectable.
- Because a refresh replaces the row, `sessions.created_at` is carried from the
  session being continued. Otherwise the session list would date every login to
  the last rotation, which for a fifteen-minute access token means "a few minutes
  ago", always. `sessions.last_activity_at` is the opposite: stamped on each
  write, so it tracks the last refresh and trails the user's real last request by
  at most one access-token lifetime.
- There is deliberately no per-request activity write. Session validation reads
  the JWT and the revocation cache and never touches `sessions`, so touching the
  row on each request would add a database round trip to every authenticated call
  to sharpen a timestamp shown in a device list. `SessionRepo.Update` existed for
  that and was never called from anywhere; it has been removed rather than left
  as an invitation.
- Presenting an already-rotated refresh token revokes **every** session the user
  has, with reason `token_reuse`. The token was accepted once already, so the
  party arriving second is holding a copy and there is no way to tell from here
  which of the two is the thief. Detection requires the matching token, not just
  the session id — an id alone travels in the access token and would otherwise
  let anyone with a stale JWT sign a victim out at will.
- Revoked sessions are persisted and cached through the revoked-session cache repository.
- Expiry and revocation are separate checks and are waived separately. They used
  to be one function behind one flag, so `isExpiredValidationSkip` — the flag a
  caller sets to read a slightly stale token — also stopped the revocation
  lookup. notification-service sets it on every websocket handshake, so a user
  who had signed out, had their sessions revoked by a password change, or been
  blocked by an admin still authenticated a new websocket for as long as their
  JWT was correctly signed. `domain.ValidateOptions` now carries the two
  separately, and the gRPC and internal-HTTP contracts map the wire flag to
  `AllowExpired` only.
- `AllowRevoked` has exactly one caller: `middleware.ValidateUserSessionForRefresh`
  on `POST /api/v1/auth/sessions/refresh`. Rotation revokes the session it
  replaces, so a replayed refresh token always arrives against a revoked session;
  refusing it in the middleware would look like hygiene and would silently
  disable reuse detection. It is a named constructor rather than a boolean so
  that reaching for it has to be deliberate.
- A revocation-cache failure fails the validation. Not knowing whether a session
  was revoked is not the same as knowing it was not.
- Known limit: notification-service validates once, at the websocket handshake.
  Revoking a session does not close a socket that is already open; it stops the
  next handshake. Dropping live connections on revocation would need a signal
  that service does not have today.
- Contact values are stored and matched in one canonical form: trimmed and
  lowercased. Without it `Alice@Example.com` and `alice@example.com` were two
  accounts on one mailbox, and signing in with a different capitalization than
  the one used at registration returned "not found". `domain.NormalizeContactValue`
  is applied at registration, sign-in and password recovery, and the database
  carries a CHECK constraint for email because admin-service writes the column
  too.
- Migration `000019` refuses to run if any two contacts differ only by case.
  Merging such accounts is a business decision -- both may hold balances in
  account-service -- so check for them before deploying:

  ```sql
  SELECT type, lower(value), count(*), array_agg(id)
  FROM contacts GROUP BY type, lower(value) HAVING count(*) > 1;
  ```

- `contacts.value` carries its own index. Sign-in and password recovery look a
  contact up by value alone, which `UNIQUE (type, value)` cannot serve -- a
  composite index is no use to a predicate that does not constrain its leading
  column. On 200k contacts that was a parallel sequential scan, 2318 buffers and
  5.9 ms per sign-in, against 12 buffers and 0.05 ms with the index, and the gap
  widens with the table.
- `POST /api/v1/internal/users/block` flags the account and ends every session it
  holds in one transaction. The two used to be separate statements, and a failure
  between them left the account flagged while its sessions kept working — the
  status is only consulted at sign-in. It answers 404 for an unknown user id
  instead of reporting success for a block that never happened; `account-service`
  calls this when a deposit or withdrawal trips AML and logs the failure.
- `POST /api/v1/verifications/init` reserves the verification row before calling
  the KYC provider. It used to read "is there an open one?", call the provider,
  then insert — so two requests arriving together both saw none, both paid for an
  applicant form, and both wrote a row. A partial unique index on
  `(user_id, provider)` for open rows is now the serialisation point: the loser
  fails at the insert and is handed the winner's form instead of buying a second.
  A reservation whose provider call failed is resumed on the next attempt, reusing
  the same `external_id` the webhook matches on.
- `JWT_ACCESS_SECRET` and `OTP_SECRET_PEPPER` are refused at startup below 32
  characters. Both are HMAC-SHA256 keys, and a key shorter than the hash output
  weakens the construction; `envconfig`'s `required` tag counts an empty value as
  set, and the constructors downstream only checked for empty, so `secret` passed
  every gate and gave HS256 six bytes of key. Generate them:
  `openssl rand -base64 32`.
- `JWT_ACCESS_SECRET` is shared with `admin-service`, which signs impersonation
  tokens this service accepts. Rotating it invalidates every access token in
  flight, so the rotation signs everyone out.
- A token must carry an `iss` this service accepts. The check used to run only
  when the claim was present, so a token with no `iss` at all was taken from
  whoever held the key. `APP_NAME` is always accepted; `JWT_ADDITIONAL_ISSUERS`
  is the comma-separated list of other services signing with the same key, and
  `admin-service` has to be in it or the backoffice notification websocket stops
  authenticating. With one shared symmetric key this buys provenance, not
  authorization — any holder of the key can write any `iss` it likes. Telling
  issuers apart for real needs a key per issuer, which the `kid`/`KeyProvider`
  seam in `JWTSessionHelper` allows and nothing configures yet.
- A TOTP code is accepted once. `two_factor_settings.last_totp_counter` holds the
  last time step spent, and the next code has to sit strictly above it, as
  RFC 6238 section 5.2 requires. Consuming the token already stopped a replay
  against the same challenge; this stops the same six digits opening a *different*
  one inside the 90 seconds the verifier accepts them. Enrolment seeds the counter
  with the step it accepted, so the code used to enrol cannot then be used to sign
  in.
- `sessions.expire` and `sessions.refresh_expire` are `BIGINT`. They held Unix
  seconds in a 32-bit `INT`, which stops at 2038-01-19 — and because
  `refresh_expire` is stamped 30 days ahead, sign-in would have begun failing on
  2037-12-20. Failing hard: Postgres refuses the insert with "integer out of
  range", so issuing a session, and therefore signing in, stops working. A
  repository test stores a session expiring past that point.
- Password hashing uses bcrypt.
- Consecutive failed sign-ins are counted per account. After
  `LOGIN_MAX_FAILED_ATTEMPTS` (default 5) the account is refused for
  `LOGIN_LOCK_DURATION` (default 15m), and the response carries `retryAfter`.
  The lock is a deadline rather than a flag, so it releases itself; a successful
  sign-in or any password rotation clears the counter. Every failure is written
  to `auth_logs` with status `login_failed`.
- The lock is an availability trade-off worth knowing about: someone who knows an
  address can keep that account locked by spending requests against it. The
  damage is bounded by the window and by the per-IP rate limit, and the owner can
  release it themselves through password recovery.
- Changing the password ends every other session of the user. `POST /api/v1/users/password-change`
  revokes them with reason `password_change`, in the same transaction that writes the new hash,
  and leaves only the session that made the request alive — clients keep working, other devices
  are signed out and their refresh tokens stop working immediately.
- Resetting a forgotten password (`POST /api/v1/users/password/reset/confirm`) ends
  **all** sessions, since the caller has none of their own — in the same
  transaction that writes the new hash. The revocation used to run after the
  commit with its error logged and dropped, so a reset could succeed while the
  session it was meant to end carried on working. A reset is what someone does
  precisely because they believe another party is holding one.
- A reset also writes `password_change_logs`, in that same transaction. It did
  not before, so `GET /api/v1/auth/me` reported the date of the *previous*
  change to a user who had just reset their password — the very field people
  check when they suspect someone else has been in the account.
- OTPs are generated locally, hashed with HMAC-based peppering, and published to the notification queue.
- Registration and session/auth flows enrich device context with GeoIP data.
- Registration may reject anonymous/VPN/proxy sources based on GeoIP anonymous-network checks.
- reCAPTCHA v3 validation is enforced in production for registration, login, and password recovery flows.
- AMLBot webhook payloads are validated through the `x-data-integrity` signature before processing.
- Nothing logs a live credential. The session helper reports token length rather
  than the token, and request/response/queue bodies pass through
  `common/logger.BodyFieldValueForLog`, which redacts passwords, tokens, OTP
  codes and provider secrets at any depth. Bodies are logged whenever
  `LOG_LEVEL=debug`, so that redaction is what makes debug safe to switch on.
- `HTTP_CLIENT_DUMP_ALL` dumps whole outbound requests and responses, including
  the AMLBot Authorization header and the reCAPTCHA secret. It is off by default
  and rejected at startup outside `local`/`dev`/`test`, the same guard
  `OTP_FIXED_CODE` has. It used to switch itself on with `LOG_LEVEL=debug`.

## Configuration

Configuration is loaded from environment variables through `config.Init()`.

Important config areas:

- app/common settings: app identity, environment, timezone, security token, JWT secret, OTP pepper
- restriction integration: HTTP and gRPC URLs
- reCAPTCHA: secret key, validation URL, minimum score
- public endpoint rate limits: `USER_*_RATE_LIMIT_RPS`, `USER_*_RATE_LIMIT_BURST`, `USER_*_RATE_LIMIT_TTL`
- KYC provider settings: AMLBot URL, token, and form IDs
- DB: connection details and pool settings
- HTTP: server port, timeouts, outbound retry/backoff
- gRPC: port, request timeout, size limits, keepalive
- queue: RabbitMQ credentials and exchange/routing-key settings
- cache: Hazelcast host/cluster and cache manager config

Use `.env.example` as the local starting point.

### Database note

`config/db.go` still accepts a configurable DB driver, but the current runtime
implementation in `cmd/user-service/app/db.go` supports PostgreSQL only.

### Security token and database TLS

`SECURITY_TOKEN` guards this service's `/api/v1/internal` endpoints and
authenticates its own calls to other services' internal endpoints.

The token must not be empty: `config.Init()` fails at startup when it is blank,
because envconfig's `required` tag only rejects an *unset* variable and an empty
token authenticates nothing.

`DB_SSL_MODE` is passed through as the PostgreSQL `sslmode` and accepts
`disable|allow|prefer|require|verify-ca|verify-full`. It defaults to `disable`
for local infrastructure; deployed environments should set at least `require`.
An unrecognized value fails at startup rather than silently downgrading the
connection. The same value is used by `cmd/commands/migrate`.

## Local development

### Prerequisites

- Go version declared in `go.mod` (`go 1.25.8` at the time of writing)
- PostgreSQL
- RabbitMQ
- Hazelcast
- local GeoIP databases:
  - `data/geoip/GeoLite2-City.mmdb`
  - `data/geoip/GeoIP2-Anonymous-IP.mmdb`
- reachable external dependencies required for the scenario under development

### Run migrations

Apply migrations:

```bash
go run ./cmd/commands/migrate --command=up
```

Check migration version:

```bash
go run ./cmd/commands/migrate --command=version
```

### Run the service

```bash
go run ./cmd/user-service
```

Default listener ports from config:

- HTTP: `8000`
- gRPC: `50051`

## Common verification commands

Run tests:

```bash
go test ./...
```

Run linters:

```bash
make lint
```

Check vulnerable dependencies:

```bash
make vulnerable-check
```

Regenerate Swagger docs after changing HTTP annotations or route docs:

```bash
make swagger-gen
```

## Generated artifacts

Generated files in this repository include:

- `docs/swagger.json`
- `docs/swagger.yaml`
- `docs/docs.go`
- `internal/transport/grpc/pb/userv1/*.pb.go`

Do not edit generated artifacts by hand. Update the source definition first,
then regenerate:

- Swagger source -> HTTP handler annotations and route wiring
- gRPC source -> `proto/user/v1/user.proto`

## Related documentation

- `AGENTS.md` for repository-local instructions for coding agents
- `internal/domain/errors/README.md` for the service error contract
- `docs/` for generated Swagger output

When documentation and code disagree, trust the current code first and then
update the docs.
