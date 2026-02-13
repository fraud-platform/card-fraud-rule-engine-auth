# AGENTS.md

This is the canonical instruction file for all coding agents working in `card-fraud-rule-engine`.

- `CLAUDE.md` must stay a thin pointer to this file.
- If any other document conflicts with this file, follow `AGENTS.md`.
- Keep docs and implementation aligned in the same PR.

## Cross-Repo Agent Standards

- Secrets: Doppler-only workflows. Do not create or commit `.env` files.
- Commands: use repository wrappers from `pyproject.toml` or `package.json`; avoid ad-hoc commands.
- Git hooks: run `git config core.hooksPath .githooks` after clone to enable pre-push guards.
- Docs publishing: keep only curated docs in `docs/01-setup` through `docs/07-reference`, plus `docs/README.md` and `docs/codemap.md`.
- Docs naming: use lowercase kebab-case for docs files. Exceptions: `README.md`, `codemap.md`, and generated contract files.
- Never commit docs/planning artifacts named `todo`, `status`, `archive`, or session notes.
- If behavior, routes, scripts, ports, or setup steps change, update `README.md`, `AGENTS.md`, `docs/README.md`, and `docs/codemap.md` in the same change.
- Keep health endpoint references consistent with current service contracts (for APIs, prefer `/api/v1/health`).
- Preserve shared local port conventions from `card-fraud-platform` unless an explicit migration is planned.
- Before handoff, run the repo's local lint/type/test gate and report the exact command + result.

## 1) Non-Negotiable Rules

### Doppler is mandatory

Do not run the app or tests with raw Maven commands.

- Dev server: `uv run doppler-local`
- Unit tests: `uv run test-unit`
- Integration tests: `uv run test-integration`
- Full test suite: `uv run test-all`

Never use:
- `mvn quarkus:dev`
- `mvn test`
- `.env` files for this repository

### Secrets model

This project uses Doppler only.

- Project: `card-fraud-rule-engine`
- Primary config: `local`

### API path casing

Evaluation endpoint paths are lowercase and case-sensitive:

- `POST /v1/evaluate/auth`
- `POST /v1/evaluate/monitoring`

Do not document or test uppercase route variants.

## 2) Quickstart For Any Agent

```bash
# 1) Install dependencies
uv sync

# 2) Start local infra (fallback compose)
uv run infra-local-up

# 3) Verify Redis
uv run redis-local-verify

# 4) Start app with Doppler secrets
uv run doppler-local
```

Recommended shared platform flow:

```bash
cd ../card-fraud-platform
uv run platform-up
uv run platform-status
cd ../card-fraud-rule-engine
uv run doppler-local
```

## 3) Command Catalog (Source: `pyproject.toml`)

### Infrastructure
- `uv run infra-local-up`
- `uv run infra-local-down`
- `uv run redis-local-up`
- `uv run redis-local-down`
- `uv run redis-local-reset`
- `uv run redis-local-verify`

### Runtime
- `uv run doppler-local`
- `uv run doppler-local-test`
- `uv run doppler-load-test`
- `uv run doppler-secrets-verify`

### Gateway Auth
- Authentication is enforced at API Gateway; rule engine does not validate tokens on-box.

### Java and E2E tests
- `uv run test-unit`
- `uv run test-smoke`
- `uv run test-integration`
- `uv run test-all`
- `uv run test-coverage`
- `uv run test-e2e`
- `uv run test-load`

### Quality
- `uv run lint`
- `uv run format`
- `uv run snyk-test`

## 4) Runtime Architecture (Current)

This service is a stateless Quarkus rule engine for card fraud decisions.

Primary responsibilities:
- AUTH evaluation: first-match, fail-open default APPROVE
- MONITORING evaluation: all-matching analytics path, requires input `decision`
- Redis velocity checks (atomic counters + Lua)
- Ruleset loading/hot reload from MinIO/S3
- Ruleset namespace is fixed to `CARD_AUTH` (AUTH) and `CARD_MONITORING` (MONITORING)
- Decision path: AUTH returns immediately after evaluation and enqueues `{tx, authDecision}` for async durability; background writer persists to Redis Streams, AUTH publisher publishes to Redpanda/Kafka with ack, and MONITORING worker is optional/off by default

Core dependencies:
- Redis 8.x
- Redpanda (Kafka API)
- MinIO (artifact read path)
- API Gateway-authenticated ingress (token verification offloaded upstream)
- Doppler secrets

## 5) API Surface (Current)

### Evaluation endpoints
- `POST /v1/evaluate/auth`
- `POST /v1/evaluate/monitoring`
- `GET /v1/evaluate/health`
- `GET /v1/evaluate/rulesets/registry/status`
- `GET /v1/evaluate/rulesets/registry/{country}`
- `POST /v1/evaluate/rulesets/hotswap`
- `POST /v1/evaluate/rulesets/load`
- `POST /v1/evaluate/rulesets/bulk-load`

### Management endpoints
- `POST /v1/manage/replay`
- `POST /v1/manage/replay/batch`
- `POST /v1/manage/simulate`
- `GET /v1/manage/metrics`

OpenAPI and UI when running:
- `http://localhost:8081/openapi`
- `http://localhost:8081/swagger-ui`

## 6) Authentication and Authorization

Token verification and scope authorization are handled by the API Gateway layer.
The rule engine trusts gateway-forwarded traffic and does not perform in-process token validation.

## 7) Test Reality (Verified 2026-02-13)

Commands executed:
- `uv run test-unit` -> PASS
- `uv run test-integration` -> PASS

Observed results:
- Unit profile: `Tests run: 504, Failures: 0, Errors: 0, Skipped: 3`
- Integration profile: `Tests run: 27, Failures: 0, Errors: 0, Skipped: 0`

Notes:
- Integration stability depended on lowercase endpoint usage in test paths.
- Keep endpoint casing normalized in all docs/tests/examples.

## 8) Documentation Policy

When behavior changes, update all relevant docs in the same change:
- `README.md`
- `AGENTS.md`
- `docs/README.md`
- `docs/codemap.md`
- `openapi/openapi.yaml` (if contract changed)

## 9) Cross-Repo Context

This repo is part of:

- `card-fraud-platform` (shared infra)
- `card-fraud-rule-management` (rules authoring + artifact publish)
- `card-fraud-transaction-management`
- `card-fraud-intelligence-portal`
- `card-fraud-e2e-load-testing`

MinIO write path is owned by rule-management.
Rule engine reads artifacts only.

## 10) Common Failure Modes

- Redis unavailable -> start with `uv run redis-local-up` or platform-up
- Doppler missing/invalid session -> run `doppler login`
- Wrong path casing (`/AUTH`, `/MONITORING`) -> use lowercase paths
- Running raw Maven directly -> switch to `uv run ...` wrappers
- Redis Streams outbox down -> AUTH must fail fast; ensure Redis is up with AOF + replica before load tests (see ADR-0014)
- Load test shows 250ms+ P50 -> do NOT use `mvn quarkus:dev` for load testing; JaCoCo agent + dev mode adds massive overhead. Use the packaged JAR instead (see `docs/04-testing/jar-based-load-testing.md`).
- LoadSheddingFilter rejects requests -> `app.load-shedding.enabled: false` in `%load-test` profile (previously defaults to 100 max-concurrent)
- Redis operations hang -> all Redis ops now have 5s bounded timeouts (configurable via `OUTBOX_REDIS_TIMEOUT_SECONDS`)

## 11) Agent Handoff Checklist

Before ending a session:
- Confirm changed commands and endpoint paths are accurate
- Run the minimum relevant test command(s)
- Run `uv run snyk-test` before push when dependency/runtime versions change
- Keep `CLAUDE.md` pointing to `AGENTS.md`
- Record only factual, verified metrics/dates

## 12) Load Testing (Critical)

**CRITICAL:** Both `uv run doppler-local` and `uv run doppler-load-test` use `mvn quarkus:dev` which includes JaCoCo instrumentation and dev mode overhead. These are NOT suitable for performance measurement.

**Measured dev mode overhead:** AUTH P50 280ms (vs 5-7ms single request) - 50x slower under load

For valid load test results, use the packaged JAR:

```bash
# Build (once)
doppler run --config local -- mvn package -DskipTests -Dquarkus.package.jar.type=uber-jar

# Run with load-test profile (disables load shedding, sets WARN logging)
doppler run --config local -- \
  java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar \
  -Dquarkus.profile=load-test
```

**See:** `docs/04-testing/jar-based-load-testing.md` for complete instructions

E2E load testing repo: `card-fraud-e2e-load-testing/`
```bash
cd C:\Users\kanna\github\card-fraud-e2e-load-testing
uv run lt-run --service rule-engine --users=200 --spawn-rate=20 --run-time=2m --scenario baseline --headless
```

**Load test configuration (`%load-test` profile):**
- `app.load-shedding.enabled: false` - Measure true capacity
- `quarkus.log.level: WARN` - Suppress hot-path logging
- `app.outbox.redis-timeout-seconds: 5` - Bounded Redis timeouts

Last updated: 2026-02-07
