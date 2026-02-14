# ADR-0003: Use HTTP 200 with In-Band FAIL_OPEN Signaling (No 503 for Handled Evaluation Errors)

**Status:** Accepted

## Context
The runtime decision engine sits on the card authorization path. We cannot assume all callers will correctly fail open on transport errors (`5xx`), and we have a hard requirement that engine-layer issues must never cause declines.

Returning `503`/`5xx` from a healthy-but-degraded engine delegates the business decision to callers and introduces hidden coupling and inconsistent behavior across integrations.

## Decision
- For **handled engine-layer failures** (dependency outages, evaluation exceptions, ruleset not loaded, etc.):
  - The runtime returns **HTTP 200**.
  - AUTH returns an explicit `decision = APPROVE`.
  - MONITORING returns an envelope with `matched_rules = []`.
  - The runtime signals degradation **in-band** using envelope fields (recommended):
    - `engine_mode`: `FAIL_OPEN` or `DEGRADED`
    - `engine_error_code`: stable string (e.g., `REDIS_UNAVAILABLE`, `RULESET_NOT_LOADED`, `ENGINE_EXCEPTION`)

MONITORING note:
- MONITORING should use `engine_mode = DEGRADED` (not `FAIL_OPEN`) since it does not produce an approve/decline business decision.

Enum standardization:
- `engine_error_code` values are locked in `docs/02-development/plan-12-engine-error-codes.md`.

ruleset version note:
- If no ruleset was actually loaded/evaluated, `ruleset_version` must be `null` (see ADR-0004).

- Exception introduced by ADR-0014 (durability guardrail):
  - AUTH may return HTTP `503` with `OUTBOX_UNAVAILABLE` when the Redis Streams outbox write fails.
  - This is a persistence guarantee failure, not an evaluation failure.
- Kafka publish failures (`EventPublishException`) are engine-layer failures:
  - Must return HTTP `200` with in-band `DEGRADED` (MONITORING) or `FAIL_OPEN` (AUTH) signaling.
  - Must NOT return `503` for Kafka publish failures. The decision was already evaluated; only persistence failed.
- Outside the outbox durability guardrail, HTTP `503`/`5xx` is acceptable only when the engine is truly unreachable (crash, network partition, DNS/LB failure), in which case there is no response.

## Rationale
- Prevents accidental declines caused by caller-specific handling of `5xx`
- Keeps the business outcome explicit and auditable
- Reduces operational risk and PR exposure

## Consequences / Requirements
- Observability becomes mandatory:
  - Metrics/alerts on fail-open/degraded rate
  - Logs must include `trace_id` and error code
- Downstream consumers must handle additional envelope fields (forward-compatible)
- Readiness checks must not unintentionally make the service unreachable during degradations
