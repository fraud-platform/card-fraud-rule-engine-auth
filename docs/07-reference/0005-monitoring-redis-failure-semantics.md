# ADR-0005: MONITORING Redis Failure Semantics

**Status:** Accepted

## Context
The runtime performs optional Redis-backed velocity checks for both AUTH and MONITORING.

For AUTH, the fail-open behavior is already locked: Redis unavailability must not block authorization decisions.

For MONITORING, Redis failure behavior must be explicitly defined to avoid inconsistent implementations and unclear downstream expectations.

## Decision
On Redis failure during MONITORING evaluation:
- The engine **skips velocity checks** (treat them as non-executed).
- The engine still evaluates non-velocity rule conditions normally.
- The response is **HTTP 200**.
- The response includes in-band degradation markers:
  - `engine_mode = DEGRADED`
  - `engine_error_code = REDIS_UNAVAILABLE` (per `docs/02-development/plan-12-engine-error-codes.md`)

## Rationale
- Aligns with the fail-open philosophy while still producing partial value.
- Prevents Redis instability from turning MONITORING into a transport-error problem.
- Keeps downstream processing stable (always receives an envelope).

## Consequences
- MONITORING match coverage may be reduced during Redis incidents.
- Observability must make this visible:
  - metrics on degraded responses
  - Redis error counters
  - logs including `trace_id`, ruleset_key, ruleset_version

## Notes
This ADR does not change AUTH semantics (still FAIL_OPEN with APPROVE on Redis failure).
