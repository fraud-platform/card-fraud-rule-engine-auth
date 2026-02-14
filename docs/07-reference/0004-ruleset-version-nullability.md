# ADR-0004: ruleset_version is Nullable in FAIL_OPEN Responses

**Status:** Accepted

## Context
`ruleset_version` is an assertion: it means “this specific ruleset version was loaded and evaluated for this transaction”.

During fail-open scenarios, the engine may approve without evaluating any rules (e.g., cold start before ruleset load, manifest unavailable, artifact load failure). In these cases, emitting a non-null `ruleset_version` would be misleading and harms auditability.

## Decision
- `ruleset_version` **must be present** when the engine actually loaded and evaluated a ruleset.
- `ruleset_version` **must be null** when the engine cannot assert that any ruleset was loaded and used (i.e., no rules were evaluated).
- Do not force “last-known-good” values when the engine did not actually evaluate a ruleset.

## Examples
### FAIL_OPEN before ruleset load
```json
{
  "transaction_id": "txn_123",
  "ruleset_key": "CARD_AUTH",
  "ruleset_version": null,
  "decision": "APPROVE",
  "engine_mode": "FAIL_OPEN",
  "engine_error_code": "RULESET_NOT_LOADED",
  "trace_id": "abc123",
  "latency_ms": 1.7
}
```

### FAIL_OPEN after ruleset load (Redis down)
```json
{
  "transaction_id": "txn_123",
  "ruleset_key": "CARD_AUTH",
  "ruleset_version": 42,
  "decision": "APPROVE",
  "engine_mode": "FAIL_OPEN",
  "engine_error_code": "REDIS_UNAVAILABLE",
  "trace_id": "abc123",
  "latency_ms": 1.9
}
```

## Rationale
- Preserves semantic honesty and auditability
- Avoids subtle correctness bugs in incident analysis and replay assumptions
- Keeps `ruleset_version` meaning stable across normal and degraded operation

## Consequences
- Consumers must tolerate `ruleset_version = null` for AUTH fail-open.
- Observability must make “no rules evaluated” states highly visible (alerts on fail-open/error code rates).
