# ADR-0002: AUTH Defaults to APPROVE and Fails OPEN on System/Dependency Failures

**Status:** Accepted

## Context
The runtime decision engine is used in the card authorization (AUTH) path. Declining transactions due to internal errors or dependency outages can cause unacceptable customer impact and revenue loss.

The original runtime spec used fail-closed semantics for certain dependency failures (notably Redis for velocity). This project now explicitly prioritizes **authorization continuity**.

## Decision
- For `CARD_AUTH`:
  - If no rules match, the engine returns `decision = APPROVE`.
  - If the engine encounters system failures or dependency failures during evaluation (including Redis velocity failures), the engine returns `decision = APPROVE` (FAIL OPEN).

Non-negotiable:
- Engine-layer issues must never be the reason for a `DECLINE` decision.

- For `CARD_MONITORING`:
  - The engine continues to return match lists; failure semantics remain a separate decision (skip velocity vs error), since MONITORING is not on the authorization hot path.

Standardization:
- In-band degradation signaling uses `engine_mode` and `engine_error_code`.
- Allowed `engine_error_code` values are locked in `docs/02-development/plan-12-engine-error-codes.md`.

MONITORING alignment:
- MONITORING must also return **HTTP 200** for handled engine-layer failures and signal degraded state in-band.
- The key functional difference between AUTH and MONITORING is execution mode/response shape:
  - AUTH: FIRST_MATCH and returns a decision
  - MONITORING: ALL_MATCHING and returns `matched_rules`

## Rationale
- Prevents false declines due to internal outages
- Keeps the runtime aligned with an enterprise “availability first” posture for authorization
- Allows fraud controls to degrade gracefully while preserving core payment flow

## Consequences / Compensating Controls
- Fraud detection efficacy may degrade during dependency incidents (especially Redis outages).
- Observability must be strong so incidents are immediately visible:
  - Metrics/alerts for Redis failures and evaluation errors
  - Structured logs with `trace_id` and enough context to quantify impact
  - Alerts for fail-open/degraded decision rate (treat as high priority)
- Consider downstream compensations (outside runtime scope):
  - MONITORING monitoring, risk analytics, manual review workflows
  - Tight SLOs for Redis and fast incident response

## Notes
This ADR intentionally changes the runtime’s safety posture. It is a business decision and should be reviewed with Fraud/Risk stakeholders.
