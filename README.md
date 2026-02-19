# Card Fraud Rule Engine (AUTH Service)

Stateless Quarkus runtime for card fraud AUTH decisioning (split from card-fraud-rule-engine on 2026-02-13).

- AUTH flow: first-match evaluation, fail-open default APPROVE
- AUTH path is hot: returns immediately after evaluation and enqueues for async durability; background workers persist to Redis Streams and publish AUTH decisions to Kafka with ack
- Redis velocity checks, MinIO ruleset loading, Kafka decision publishing
- Supported runtime ruleset keys are fixed to `CARD_AUTH` (no per-transaction-type ruleset namespaces)

## Quick Start

Prerequisites:
- Java 25+
- Maven 3.9+
- Python 3.11+
- `uv`
- Docker
- Doppler CLI

```bash
# 1) Install deps
uv sync

# 2) Bring up local infra (or use card-fraud-platform)
uv run infra-local-up
uv run redis-local-verify

# 3) Start service with Doppler secrets
uv run doppler-local
```

Service URLs:
- OpenAPI: `http://localhost:8081/openapi`
- Swagger UI: `http://localhost:8081/swagger-ui`
- Health: `http://localhost:8081/v1/evaluate/health`

## API Endpoints

Evaluation:
- `POST /v1/evaluate/auth`
- `GET /v1/evaluate/health`
- `GET /v1/evaluate/rulesets/registry/status`
- `GET /v1/evaluate/rulesets/registry/{country}`
- `POST /v1/evaluate/rulesets/hotswap`
- `POST /v1/evaluate/rulesets/load`
- `POST /v1/evaluate/rulesets/bulk-load`

Management:
- `POST /v1/manage/replay`
- `POST /v1/manage/replay/batch`
- `POST /v1/manage/simulate`
- `GET /v1/manage/metrics`

## Test Commands

```bash
uv run test-unit
uv run test-smoke
uv run test-integration
uv run test-all
uv run test-coverage
uv run snyk-test
```

## Security and Secrets

Doppler is mandatory for runtime/test commands.
Authentication and authorization are enforced at API Gateway.
Rule engine no longer validates tokens in-process.

Use:
- `uv run doppler-local`
- `uv run test-unit`

Do not use:
- `mvn quarkus:dev`
- `mvn test`
- `.env` files in this repository

Ruleset loading for runtime/replay uses compiled artifacts (`ruleset.json` via manifest) to mirror production behavior.

## Documentation

- Agent instructions: `AGENTS.md`
- Docs index: `docs/README.md`
- Setup guides: `docs/01-setup/`
- ADRs: `docs/07-reference/`
- Runbooks: `docs/06-operations/`

## Split Baseline

This repo was created from `card-fraud-rule-engine` baseline tag `split-baseline-2026-02-13`.
See `AGENTS.md` for split execution details.
