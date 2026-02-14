# ADR-0015: Scope Bucket Traversal Order for AUTH Evaluation

**Status:** Accepted
**Date:** 2026-02-06
**Owners:** Rule Engine Team

## Context

AUTH evaluation must produce deterministic, explainable decisions. Rules have scope dimensions (network, bin, mcc, logo) that narrow applicability. The evaluation order must be locked so that more specific rules always take precedence over less specific ones, and ties are broken predictably.

Previously, the evaluator iterated all rules sorted by global priority only. Scope bucketing was computed in `Ruleset.getApplicableRules()` but the result was not consumed by evaluators (they iterated `getRulesByPriority()` instead).

## Decision

### Evaluation Order (Pre-Auth)

1. **Scope bucket specificity** (most specific first, country-only/global last)
2. **Priority** within each bucket (higher numeric priority first)
3. **Decision tie-breaker** for equal specificity + priority: `APPROVE` before non-APPROVE

### Specificity Ranking

| Scope Type | Specificity | Description |
|------------|-------------|-------------|
| COMBINED | 5 | Multiple dimensions (AND across dimensions) |
| LOGO | 4 | Card product type |
| MCC | 3 | Merchant category code |
| BIN | 2 | Bank identification number (prefix match) |
| NETWORK | 1 | Card network (VISA, MASTERCARD, etc.) |
| GLOBAL | 0 | No scope (applies to all transactions) |

### Scope Semantics

- OR within each scope dimension array (e.g., `network: ["VISA", "MASTERCARD"]` matches either)
- AND across dimensions in COMBINED scopes (all dimensions must match)
- No wildcard scope values
- Empty scope `{}` = GLOBAL (applies to all)

### AUTH Short-Circuit

AUTH uses FIRST_MATCH semantics. Once the comparator-ordered traversal finds a matching rule, evaluation stops and returns that rule's decision.

### MONITORING Semantics

MONITORING collects all matching rules. The comparator ordering determines the order of `matched_rules` in the response but does not affect the final decision (MONITORING does not produce APPROVE/DECLINE from rules; it carries the caller-provided decision).

## Rationale

- Scope-first ordering ensures a BIN-specific rule always beats a NETWORK-specific rule, regardless of numeric priority
- APPROVE-first tie-breaking reflects fraud ops design intent: when specificity and priority are equal, prefer allowing the transaction
- Deterministic ordering makes evaluation explainable and auditable

## Implementation

- `Ruleset.getApplicableRules()` returns rules sorted by the locked comparator
- `EvaluationContext` carries the scoped candidate rules list
- `AuthEvaluator` and `MonitoringEvaluator` consume `context.getRulesToEvaluate()` instead of `ruleset.getRulesByPriority()`

## Consequences

- Rule evaluation order may change for existing rulesets that have rules with different scope types. Previously, a high-priority GLOBAL rule could evaluate before a low-priority BIN-specific rule. Now the BIN-specific rule always evaluates first.
- Test rulesets without scopes are unaffected (all rules are GLOBAL, so ordering falls back to priority-only).
