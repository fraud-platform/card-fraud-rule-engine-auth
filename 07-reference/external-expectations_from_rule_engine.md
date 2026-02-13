# Expectations from card-fraud-rule-engine

This document specifies the data contract that **card-fraud-transaction-management**
expects from the **card-fraud-rule-engine** runtime service.

## Decision Events (Authoritative)

The rule engine MUST emit decision events for every evaluation, including:
- normal decisions
- fail-open decisions
- load-shed decisions

Events are published to Kafka topic `fraud.card.decisions.v1`.

Schema reference: `docs/openapi-transaction-management.json`

## Required/Expected Fields

At minimum, every event should include:

```json
{
  "transaction_id": "string (required, stable business ID)",
  "occurred_at": "ISO8601 timestamp (required)",
  "produced_at": "ISO8601 timestamp (required)",
  "transaction": { "card_id": "string (required)" },
  "decision": "APPROVE | DECLINE (required)",
  "decision_reason": "RULE_MATCH | VELOCITY_MATCH | SYSTEM_DECLINE | DEFAULT_ALLOW (required)",
  "evaluation_type": "AUTH | MONITORING (required)",
  "ruleset_key": "string (expected, may be null on fail-open)",
  "ruleset_version": "int (expected, may be null on fail-open)",
  "ruleset_id": "uuid (expected, may be null on fail-open)"
}
```

Additional fields are expected when available:
- `matched_rules`
- `velocity_results`
- `velocity_snapshot`
- `transaction_context`
- `engine_metadata`

## Decision Semantics

### AUTH
- First-match semantics
- Decisions are **APPROVE or DECLINE only**
- `matched_rules` has **at most one** rule (can be empty if no rule matched)

### MONITORING (analytics-only)
- All-match semantics (collect all matching rules)
- Engine does **not** derive a decision from matched rules
- Decision is **set from request `decision`** (APPROVE/DECLINE)
- If `decision` is missing or invalid, engine rejects the request (HTTP 400) and does not emit a decision event

## Matched Rules

Each matched rule should include (when available):

```json
{
  "rule_id": "string (required)",
  "rule_version_id": "uuid (required)",
  "rule_version": "int (optional)",
  "rule_name": "string (optional)",
  "priority": "int (optional)",
  "action": "APPROVE | DECLINE | REVIEW (required)",
  "conditions_met": ["..."],
  "condition_values": { "...": "..." },
  "matched_at": "ISO8601 timestamp (optional)",
  "match_reason_text": "string (optional)"
}
```

## Velocity Results

Two velocity structures are expected:

- `velocity_results`: per-rule velocity outcomes (exceeded or not)
- `velocity_snapshot`: full velocity state at decision time (read-only)

## Engine Metadata

`engine_metadata` should contain:
- `engine_mode`: NORMAL | DEGRADED | FAIL_OPEN
- `error_code`: e.g. REDIS_UNAVAILABLE, RULESET_NOT_FOUND, INTERNAL_ERROR, EVALUATION_ERROR, LOAD_SHEDDING, MISSING_DECISION, INVALID_DECISION
- `error_message`
- `processing_time_ms`

Fail-open always returns `decision = APPROVE` and `engine_mode = FAIL_OPEN`.

## Delivery & Idempotency

- At-least-once delivery is expected.
- Transaction-management should accept **multiple events per transaction_id**
  when `evaluation_type` or `occurred_at` differs.
- Events are immutable; new events are emitted instead of updates.

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 3.0 | 2026-01-27 | Aligned with evaluation_type, ruleset identifiers, velocity_results, MONITORING analytics-only behavior |
| 2.0 | 2026-01-25 | Added transaction_context, velocity_snapshot, conditions_met, engine_metadata |
| 1.0 | 2026-01-17 | Initial specification |
