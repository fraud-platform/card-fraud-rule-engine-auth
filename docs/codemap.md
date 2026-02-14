# Code Map

## Repository Purpose

Quarkus runtime for fraud decision evaluation and compiled ruleset execution. AUTH is latency-critical and returns immediately after evaluation (including Redis velocity checks). Durability/eventing is handled asynchronously via a background Redis Streams writer and an AUTH Kafka publisher (with ack) off the request thread; the legacy MONITORING outbox worker is optional and off by default.

Ruleset resolution uses `CARD_AUTH` for AUTH and `CARD_MONITORING` for MONITORING. Resolution is country-aware: the engine looks up `rulesetRegistry.getRuleset(countryCode, key)` with fallback to global namespace.

AUTH evaluation order: scope bucket specificity (most specific first) -> priority -> APPROVE-first tie-breaker (ADR-0015).

AUTH hot-path performance rules:
- AUTH request thread must not block on outbox/Kafka durability (ADR-0018).
- Redis Streams consumer-group retry semantics require pending recovery (ADR-0019).

## Documentation Layout

- `01-setup/`: Setup
- `02-development/`: Development
- `03-api/`: API
- `04-testing/`: Testing
- `05-deployment/`: Deployment
- `06-operations/`: Operations
- `07-reference/`: Reference

## Local Commands

- `uv sync`
- `uv run doppler-local`
- `uv run test-unit`
- `uv run snyk-test`

## Platform Modes

- Standalone mode: run this repository with its own local commands and Doppler config.
- Consolidated mode: run via `card-fraud-platform` for cross-service local validation.
