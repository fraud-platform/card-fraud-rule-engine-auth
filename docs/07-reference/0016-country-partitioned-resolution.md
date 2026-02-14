# ADR-0016: Country-Partitioned Ruleset Resolution

**Status:** Accepted
**Date:** 2026-02-06
**Owners:** Rule Engine Team

## Context

The locked runtime design requires:
- One transaction maps to exactly one country ruleset context
- No cross-country rule evaluation
- Runtime deploys per region and may cache multiple countries

The current implementation uses a global namespace (`"global"`) for all rulesets. The `RulesetRegistry` supports country-keyed lookups (`getRuleset(country, key)`) but the hot path (`EvaluationResource`) always passes `"global"`.

## Decision

### Hot-Path Resolution

1. Extract `country_code` from `TransactionContext`
2. Look up `rulesetRegistry.getRuleset(countryCode, rulesetKey)`
3. If not found, fall back to `rulesetRegistry.getRuleset("global", rulesetKey)`
4. If neither found, return fail-open APPROVE (AUTH) or DEGRADED (MONITORING)

### Fallback Semantics

The global fallback ensures backward compatibility:
- Rulesets loaded without country (e.g., via bulk-load with `country: "global"`) continue to work
- Country-specific rulesets take precedence when available
- No transaction is ever evaluated against rules from a different country

### Worker Resolution

The `MonitoringOutboxWorker` uses the same fallback logic when looking up MONITORING rulesets for outbox-driven evaluation.

### Registry API

```java
// New method with fallback
public Ruleset getRulesetWithFallback(String country, String rulesetKey) {
    Ruleset countrySpecific = getRuleset(country, rulesetKey);
    if (countrySpecific != null) return countrySpecific;
    return getRuleset("global", rulesetKey);
}
```

### Hot Reload

Hot reload is country-isolated:
- Only rulesets for the changed country are reloaded
- Other countries remain unaffected
- On failure: keep last-known-good version and emit structured alert with `country`, `artifact_type`, `version`

## Rationale

- Supports multi-country deployments from a single engine instance
- Backward compatible with existing global-only loading
- Matches the locked runtime design for region/country partitioning
- No S3 layout changes required for this phase (country awareness in registry only)

## Future Work

- S3 object layout: `rulesets/{env}/{region}/{country}/{artifact_type}/manifest.json`
- Startup full-preload of all countries under configured region
- Readiness gate blocked until full preload succeeds

## Consequences

- Country code in transaction is now semantically meaningful for ruleset selection
- Transactions without `country_code` fall back to global rulesets
- Load/bulk-load endpoints accept `country` parameter (already supported)
