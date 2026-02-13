# ADR-0009: Compiled Ruleset with Debug Mode

**Status:** APPROVED
**Date:** 2025-01-23
**Author:** Code Review Discussion
**Implemented:** 2025-01-23

---

## 1. Context

### 1.1 Problem Statement

We have two code paths for rule evaluation:
1. **Regular Ruleset**: Uses HashMap-based field access, easier to debug
2. **Compiled Ruleset**: Uses lambda-based direct array access, faster but harder to debug

The current code has a TODO comment acknowledging a "temporary bridge" where `EvaluationResource` falls back to loading YAML for compiled rulesets instead of using them directly.

### 1.2 Stakeholder Concerns

| Concern | Description |
|----------|-------------|
| **Performance** | Compiled ruleset provides 2-5x faster evaluation |
| **Debuggability** | Developers want to understand which rules matched and why |
| **Consistency** | "What works in dev should work the same everywhere" |
| **Audit Trail** | Transaction management needs full matched rule details |

---

## 2. Decision

### 2.1 Use Compiled Ruleset Everywhere

**Decision:** All environments (dev, test, staging, prod) **MUST** use the same compiled ruleset code path.

**Rationale:**
- Different code paths in different environments is a recipe for production bugs
- Performance issues only show up under load in production
- "Works on my machine" is not acceptable

### 2.2 Add Debug Mode Toggle

**Decision:** Introduce a debug mode flag that controls the verbosity of evaluation without changing the execution path.

```java
// Configuration
app.evaluation.debug.enabled=false  # Default: off for performance

// In Decision class
@JsonProperty("debug_info")
private DebugInfo debugInfo;  // Only populated when debug=true
```

**Behavior:**
| Debug Mode | Off (default) | On |
|------------|-----------------|-----|
| **Code Path** | Compiled ruleset | Same compiled ruleset |
| **Execution** | Direct array access | Same direct array access |
| **Decision.matchedRules** | Populated (as before) | Populated (as before) |
| **Decision.debugInfo** | `null` | Contains condition details, field values, timing |

### 2.3 Publish Full Matched Rules to Kafka

**Current State:**
```java
// DecisionEvent - Only sends COUNTS
event.matchedRulesCount = decision.getMatchedRules().size();
event.velocityAlertsCount = ...;
```

**Enhanced State:**
```java
// DecisionEvent - Sends FULL DETAILS
event.matchedRules = decision.getMatchedRules();  // Full list with details
event.velocityResults = decision.getVelocityResults();
```

This ensures transaction-management has all debugging information available regardless of engine implementation details.

---

## 3. Technical Design

### 3.1 DebugInfo Structure

```java
package com.fraud.engine.domain;

public record DebugInfo(
    List<ConditionEvaluation> conditionEvaluations,
    Map<String, Object> fieldValues,
    long compilationTimestamp,
    String compiledRulesetVersion
) {

    public record ConditionEvaluation(
        String ruleId,
        String conditionId,  // For multi-condition rules
        String field,
        String operator,
        Object expectedValue,
        Object actualValue,
        boolean matched
    ) {}
}
```

### 3.2 Configuration

```properties
# application.properties
app.evaluation.debug.enabled=false
app.evaluation.debug.includeFieldValues=true
app.evaluation.debug.maxConditionEvaluations=100
```

### 3.3 Code Changes

**Step 1:** Add debug info builder in `RuleEvaluator`

```java
private Decision populateDebugInfo(Decision decision, Ruleset ruleset,
                                     TransactionContext transaction,
                                     List<Rule> matchedRules) {
    if (!debugEnabled) {
        return;
    }

    DebugInfo debugInfo = new DebugInfo();
    debugInfo.compilationTimestamp = ruleset.getCompiledAt();

    for (Rule rule : matchedRules) {
        for (Condition condition : rule.getConditions()) {
            ConditionEvaluation eval = new ConditionEvaluation();
            eval.ruleId = rule.getId();
            eval.field = condition.getField();
            eval.operator = condition.getOperator();
            eval.expectedValue = condition.getValue();
            eval.actualValue = transaction.toEvaluationContext().get(condition.getField());
            eval.matched = condition.evaluate(transaction.toEvaluationContext());
            debugInfo.conditionEvaluations.add(eval);
        }
    }

    decision.setDebugInfo(debugInfo);
}
```

**Step 2:** Update `Decision` class

```java
@JsonProperty("debug_info")
private DebugInfo debugInfo;  // Only populated when app.evaluation.debug.enabled=true
```

**Step 3:** Update `DecisionPublisher` to send full details

```java
// Remove this - we don't need simplified counting anymore
// event.matchedRulesCount = decision.getMatchedRules().size();

// Send full matched rules instead
event.matchedRules = decision.getMatchedRules();
event.velocityResults = decision.getVelocityResults();
```

---

## 4. Performance Considerations

### 4.1 Debug Mode Overhead

| Component | Overhead | Notes |
|-----------|----------|-------|
| **DebugInfo object creation** | Only when `debug=true` | Negligible |
| **Field value extraction** | Only when `debug=true` | Uses existing `toEvaluationContext()` |
| **JSON serialization** | Only when `debug=true` | Already serializing Decision anyway |

**Impact:** Zero overhead when debug=false (default). Small overhead when enabled.

### 4.2 Memory Impact

- **No change to hot path allocations** when debug=false
- When debug=true: additional DebugInfo object per decision
- Can be rate-limited to prevent abuse (e.g., sample 1% of requests)

---

## 5. Implementation Tasks

### 5.1 Phase 1: Core Debug Infrastructure
- [ ] Add `app.evaluation.debug.enabled` configuration
- [ ] Create `DebugInfo` and `ConditionEvaluation` records
- [ ] Add `debugInfo` field to `Decision` class
- [ ] Implement `populateDebugInfo()` in `RuleEvaluator`

### 5.2 Phase 2: Kafka Event Enhancement
- [ ] Update `DecisionEvent` to include full matched rules
- [ ] Update `DecisionPublisher.toEvent()` method
- [ ] Update transaction-management to consume enhanced events

### 5.3 Phase 3: Compiled Ruleset Direct Usage
- [x] Remove `convertToRuleset()` fallback in `EvaluationResource`
- [x] Implement `RuleEvaluator.evaluate(CompiledRuleset)` overload
- [x] Update evaluation path to use compiled ruleset directly

### 5.4 Phase 4: Debug Controls
- [x] Add rate limiting for debug mode
- [x] Add sampling percentage configuration
- [ ] Add debug log level toggle

---

## 6. Trade-offs

| Aspect | Chosen Approach | Alternative | Rejected |
|--------|----------------|--------------|----------|
| **Code Path** | Same compiled ruleset everywhere | Separate regular/compiled paths | Different paths = prod bugs |
| **Debug Data Location** | In Decision object (conditional) | Separate debug endpoint | Breaks audit trail |
| **Performance Impact** | Zero when off, small when on | Always include debug info | Wastes CPU/memory |
| **Testing Strategy** | Same code path = valid tests | Needs separate debug tests | Tests may miss bugs |

---

## 7. Related Documentation

- **Technical Design:** `docs/02-development/technical-03-domain-models.md` - Add DebugInfo record
- **Interface Definitions:** `docs/02-development/technical-02-interface-definitions.md` - Update DecisionEnvelope
- **API Documentation:** Update OpenAPI specs for debug response fields

---

## 8. Open Questions

1. **Should debug mode be tied to engine mode?** (e.g., always enable when engineMode=DEGRADED)
2. **Should we include field values in debug output?** (potential PII concern)
3. **Should debug mode be rate limited?** If so, what's the default rate?

---

## 9. Implementation Status

**Date:** 2025-01-23

### Implemented Features

| Feature | Status | Notes |
|---------|--------|-------|
| EvaluationConfig class | ✅ Complete | `config/EvaluationConfig.java` |
| DebugInfo domain model | ✅ Complete | `domain/DebugInfo.java` |
| Decision.debugInfo field | ✅ Complete | Added to Decision.java |
| Debug info population | ✅ Complete | RuleEvaluator updated |
| Compiled ruleset direct support | ✅ Complete | RuleEvaluator.evaluate(CompiledRuleset) |
| Removed convertToRuleset fallback | ✅ Complete | EvaluationResource updated |
| Debug sampling support | ✅ Complete | sampleRate configuration |
| Max condition evaluations limit | ✅ Complete | maxConditionEvaluations config |

### Configuration Options

```properties
# Available in application.properties
app.evaluation.debug.enabled=false
app.evaluation.debug.includeFieldValues=true
app.evaluation.debug.maxConditionEvaluations=100
app.evaluation.debug.sampleRate=100
```

### Test Coverage

- DebugInfoTest: 5/5 passed
- RuleEvaluatorTest: 13/13 passed
- DecisionTest: 12/12 passed
- Total: 30 tests, 0 failures

---

## 10. Approval Status

**Status:** APPROVED
**Approved By:** Code Review Team
**Date:** 2025-01-23

---

**End of ADR**
