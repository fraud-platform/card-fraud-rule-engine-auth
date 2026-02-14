# Inline Ruleset Simulation Feature

**Document:** `inline-simulation-design.md`
**Status:** IMPLEMENTED
**Date:** 2025-01-23
**Implementation:** 2025-01-23

---

## 1. Overview

This document describes a testing feature that allows fraud analysts and developers to test rules without deploying them.

---

## 2. Problem Statement

### Current Workflow (Slow)

1. Create/edit YAML ruleset file
2. Upload to S3/MinIO storage
3. Trigger hot reload or wait for cache refresh
4. Send test transaction
5. Check results
6. If wrong: go back to step 1

**Time per iteration:** 2-5 minutes

### Desired Workflow (Fast)

1. Submit transaction + inline ruleset YAML in single API call
2. Get immediate results with explanation
3. Tweak and retry

**Time per iteration:** 5-10 seconds

---

## 3. Use Cases

| User | Use Case | Example |
|------|----------|---------|
| **Fraud Analyst** | Test new rule patterns before committing | "Would this catch transactions from NG over $1000?" |
| **Rule Developer** | Debug condition logic | "Why isn't my IN operator working?" |
| **QA Engineer** | Regression testing without deployment | "Test edge cases against ruleset v5" |
| **Support** | Reproduce customer scenarios | "Why was transaction xyz declined?" |

---

## 4. API Design

### 4.1 Endpoint

```
POST /v1/manage/simulate
```

### 4.2 Request

```json
{
  "transaction": {
    "transaction_id": "test-sim-001",
    "card_hash": "abc123hash",
    "amount": 5000,
    "currency": "USD",
    "country_code": "NG",
    "merchant_id": "merchant_123",
    "merchant_category": "electronics",
    "timestamp": "2025-01-23T10:30:00Z"
  },
  "rulesetYaml": "key: TEST_SIMULATION\nevaluation_type: AUTH\nrules:\n  - id: test-rule-1\n    name: 'High Amount Nigeria'\n    action: DECLINE\n    priority: 100\n    conditions:\n      - field: amount\n        operator: gt\n        value: 1000\n      - field: country_code\n        operator: in\n        values: [NG, RU, PK]\n      - field: card_present\n        operator: eq\n        value: false"
}
```

### 4.3 Response

```json
{
  "transaction_id": "test-sim-001",
  "decision": "DECLINE",
  "matchedRules": [
    {
      "ruleId": "test-rule-1",
      "ruleName": "High Amount Nigeria",
      "action": "DECLINE",
      "priority": 100,
      "conditionsMet": [
        "amount(5000) > 1000 = true",
        "country_code(NG) in [NG, RU, PK] = true",
        "card_present(false) == false = true"
      ]
    }
  ],
  "explanation": "Rule 'test-rule-1' matched: all 3 conditions satisfied",
  "evaluatedAt": "2025-01-23T10:30:05Z",
  "evaluationTimeMs": 2
}
```

### 4.4 Velocity Simulation (Optional Enhancement)

For rules with velocity configuration:

```json
{
  "transaction": { ... },
  "rulesetYaml": "...",
  "velocityOverrides": {
    "test-rule-1": {
      "currentCount": 5,
      "threshold": 3,
      "exceeded": true
    }
  }
}
```

---

## 5. Implementation Design

### 5.1 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Simulation Endpoint                        │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────┐ │
│  │ Parse YAML      │ -> │ Compile Ruleset  │ -> │ Evaluate   │ │
│  │ (inline)        │    │ (in-memory)      │    │ (Decision) │ │
│  └─────────────────┘    └──────────────────┘    └────────────┘ │
│                                                                  │
│  Key difference: NO caching, NO S3, NO Kafka publishing          │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Service Layer

```java
@ApplicationScoped
public class SimulationService {

    @Inject
    RulesetLoader rulesetLoader;

    @Inject
    RuleEvaluator ruleEvaluator;

    /**
     * Simulates evaluation with an inline ruleset.
     *
     * Unlike normal evaluation:
     * - No caching (ruleset compiled in-memory each time)
     * - No Kafka publishing (results returned directly)
     * - No Redis writes (read-only for velocity)
     * - Enhanced explanation output
     */
    public SimulationResult simulate(
            TransactionContext transaction,
            String rulesetYaml) {

        // 1. Parse inline YAML
        Ruleset ruleset = yamlMapper.readValue(rulesetYaml, Ruleset.class);

        // 2. Compile to in-memory CompiledRuleset
        CompiledRuleset compiled = compile(ruleset);

        // 3. Evaluate with explanation enabled
        Decision decision = ruleEvaluator.evaluateWithExplanation(
            transaction, compiled);

        // 4. Build enhanced response
        return buildSimulationResult(decision);
    }

    private SimulationResult buildSimulationResult(Decision decision) {
        SimulationResult result = new SimulationResult();
        result.setTransactionId(decision.getTransactionId());
        result.setDecision(decision.getDecision());

        // Add human-readable explanations
        for (MatchedRule matched : decision.getMatchedRules()) {
            result.addMatchedRule(matched);
            result.addExplanation(buildExplanation(matched));
        }

        return result;
    }

    private String buildExplanation(MatchedRule matched) {
        StringBuilder sb = new StringBuilder();
        sb.append("Rule '").append(matched.getRuleName())
          .append("' matched: ");

        List<String> conditions = matched.getConditionsMet();
        if (conditions != null && !conditions.isEmpty()) {
            sb.append("all ").append(conditions.size())
              .append(" conditions satisfied");
            for (String c : conditions) {
                sb.append("\n  - ").append(c);
            }
        }

        return sb.toString();
    }
}
```

### 5.3 Resource Layer

```java
@POST
@Path("/simulate")
@Authenticated
@Operation(summary = "Simulate with custom ruleset", description = "Test with ad-hoc ruleset content")
@APIResponse(responseCode = "200", description = "Simulation complete")
public Response simulate(SimulationRequest request) {

    // Validate scope
        return Response.status(Response.Status.FORBIDDEN)
                .entity(new ErrorResponse("MISSING_SCOPE", "Required scope: replay:transactions"))
                .build();
    }

    try {
        SimulationResult result = simulationService.simulate(
            request.getTransaction(),
            request.getRulesetYaml()
        );
        return Response.ok(result).build();

    } catch (InvalidRulesetException e) {
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(new ErrorResponse("INVALID_RULESET", e.getMessage()))
                .build();
    } catch (Exception e) {
        return Response.serverError()
                .entity(new ErrorResponse("SIMULATION_ERROR", e.getMessage()))
                .build();
    }
}
```

---

## 6. Security Considerations

| Concern | Mitigation |
|---------|------------|
| **Unauthorized rule testing** | Require `replay:transactions` scope |
| **Resource exhaustion** | Limit ruleset size, timeout after 30s |
| **Injection attacks** | Validate YAML schema, limit rule count |
| **PII exposure** | Don't persist simulation results, only log on error |

---

## 7. Implementation Tasks

| Priority | Task | Effort | Status |
|----------|------|--------|--------|
| P0 | Create `SimulationService` class | Medium | ✅ Complete |
| P0 | Implement inline YAML parsing | Low | ✅ Complete |
| P0 | Wire up `/simulate` endpoint | Low | ✅ Complete |
| P1 | Add enhanced explanation builder | Medium | ✅ Complete |
| P1 | Add velocity override support | Medium | Pending (future enhancement) |
| P2 | Add batch simulation (multiple transactions) | Low | Pending |
| P2 | Add simulation history (last N requests) | Low | Pending |

---

## 8. Testing Strategy

```java
@QuarkusTest
public class SimulationServiceTest {

    @Test
    void shouldEvaluateInlineRuleset() {
        String yaml = """
            key: TEST
            evaluation_type: AUTH
            rules:
              - id: r1
                name: "Test Rule"
                action: DECLINE
                conditions:
                  - field: amount
                    operator: gt
                    value: 1000
            """;

        TransactionContext txn = createTransaction(5000);
        SimulationResult result = simulationService.simulate(txn, yaml);

        assertEquals("DECLINE", result.getDecision());
        assertTrue(result.getMatchedRules().size() > 0);
    }

    @Test
    void shouldProvideDetailedExplanation() {
        // Test that conditions are clearly explained
        // e.g., "amount(5000) > 1000 = true"
    }
}
```

---

## 9. Related Documentation

- **ADR-0009:** Compiled Ruleset Debug Mode - shares explanation format
- **API Documentation:** Update OpenAPI specs for `/v1/manage/simulate`
- **Testing Strategy:** `docs/02-development/plan-10-testing-strategy-plan.md`

---

## 10. Implementation Status

**Implemented:** 2025-01-23

### Files Created

| File | Description |
|------|-------------|
| `simulation/SimulationService.java` | Core simulation service |
| `resource/dto/SimulationResult.java` | Response DTO |
| `resource/dto/SimulationRequest.java` | Updated with includeDebug flag |
| `domain/DebugInfo.java` | Debug domain model (shared with debug mode) |

### Files Modified

| File | Changes |
|------|---------|
| `resource/ManagementResource.java` | Implemented /simulate endpoint |
| `domain/Decision.java` | Added debugInfo field |

### Endpoint

```
POST /v1/manage/simulate
Authorization: Bearer <token>
Scope: replay:transactions

Response 200 OK:
{
  "transaction_id": "test-001",
  "decision": "DECLINE",
  "ruleset_key": "TEST_SIMULATION",
  "matched_rules": [...],
  "explanations": ["Rule 'High Amount' matched..."],
  "explanation": "Rule 'High Amount' matched with action DECLINE",
  "evaluated_at": "2025-01-23T10:30:00Z",
  "evaluation_time_ms": 5
}
```

### Pending Enhancements

- Batch simulation (multiple transactions)
- Velocity override support for testing velocity rules
- Simulation history caching

---

**End of Document**
