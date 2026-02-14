# Card Fraud Rule Engine Documentation

Quarkus runtime for fraud decision evaluation and compiled ruleset execution.

## Quick Start

```powershell
uv sync
uv run doppler-local
uv run test-unit
uv run snyk-test
```

## Documentation Standards

- Keep published docs inside `docs/01-setup` through `docs/07-reference`.
- Use lowercase kebab-case file names for topic docs.
- Exceptions: `README.md`, `codemap.md`, and generated contract artifacts (for example `openapi.json`).
- Do not keep TODO/archive/status/session planning docs in tracked documentation.

## Section Index

### `01-setup` - Setup

Prerequisites, first-run onboarding, and environment bootstrap.

- `01-setup/doppler-secrets-setup.md`
- `01-setup/redis-setup.md`

### `02-development` - Development

Day-to-day workflows, architecture notes, and contributor practices.

- `02-development/architecture.md`
- `02-development/gc-optimization.md`
- `02-development/http2-guide.md`
- `02-development/inline-simulation-design.md`
- `02-development/jvm-warmup.md`
- `02-development/kafka-optimization.md`
- `02-development/performance-tuning-plan.md`
- `02-development/performance-tuning.md`
- `02-development/redis-lua-optimization.md`
- `02-development/redis-tuning.md`

### `03-api` - API

Contracts, schemas, endpoint references, and integration notes.

- `03-api/decision-event-schema-v2.md`
- `03-api/field-registry-contract.md`
- `03-api/openapi-transaction-management.json`
- `03-api/rule-management-requirements.md`
- `03-api/rule-schema.md`

### `04-testing` - Testing

Test strategy, local commands, and validation playbooks.

- `04-testing/e2e-testing.md`
- `04-testing/auth-only-slo-and-async-durability.md`
- `04-testing/load-testing-baseline.md`
- `04-testing/performance-findings-summary.md`
- `04-testing/powershell-load-testing-runbook.md`

Load testing defaults to pre-loading compiled `CARD_AUTH` and `CARD_MONITORING` rulesets before traffic generation.

### `05-deployment` - Deployment

Local runtime/deployment patterns and release-readiness guidance.

- `05-deployment/native-image-guide.md`

### `06-operations` - Operations

Runbooks, observability, troubleshooting, and security operations.

- `06-operations/artifact-retention-policy.md`
- `06-operations/checksum-mismatch.md`
- `06-operations/disaster-recovery.md`
- `06-operations/elevated-fail-open-rate.md`
- `06-operations/manifest-query-failure.md`
- `06-operations/multi-region-strategy.md`
- `06-operations/redis-outage.md`
- `06-operations/redis-velocity-and-replay.md`
- `06-operations/ruleset-reload-loop.md`
- `06-operations/slos.md`

### `07-reference` - Reference

ADRs, glossary, and cross-repo reference material.

- `07-reference/0001-runtime-reads-manifest-directly.md`
- `07-reference/0002-auth-fail-open-default-approve.md`
- `07-reference/0003-http-200-inband-fail-open.md`
- `07-reference/0004-ruleset-version-nullability.md`
- `07-reference/0005-monitoring-redis-failure-semantics.md`
- `07-reference/0006-api-versioning-strategy.md`
- `07-reference/0007-null-and-missing-field-semantics.md`
- `07-reference/0008-runtime-reads-s3-manifest-only.md`
- `07-reference/0009-compiled-ruleset-debug-mode.md`
- `07-reference/0010-rate-limiting-strategy.md`
- `07-reference/0012-domain-model-merge.md`
- `07-reference/0013-zero-overhead-debug.md`
- `07-reference/0014-auth-monitoring-redis-streams-outbox.md`
- `07-reference/0018-auth-hot-path-auth-only-async-durability.md`
- `07-reference/0019-redis-streams-pending-recovery-and-retries.md`
- `07-reference/external-expectations_from_rule_engine.md`

Auth model note:
- Authentication/authorization is enforced at API Gateway; rule engine docs assume trusted ingress.

## Core Index Files

- `docs/README.md`
- `docs/codemap.md`
