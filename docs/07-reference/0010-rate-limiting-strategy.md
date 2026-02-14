# ADR-0010: Rate Limiting Strategy

**Status:** Accepted
**Date:** 2026-01-24
**Decision Makers:** Platform Team, Fraud Engineering

## Context

The card-fraud-rule-engine needs a strategy for handling request volume beyond capacity. As a critical path service for payment authorization, the approach must balance:

1. **Availability**: Transactions should not be blocked unnecessarily
2. **Protection**: The service must not be overwhelmed by traffic spikes
3. **Consistency**: Behavior should be predictable across all scenarios

### Traffic Patterns

- Normal: ~5,000 TPS (transactions per second)
- Peak: ~15,000 TPS (holiday shopping, flash sales)
- Anomaly: >50,000 TPS (bot attacks, DDoS, upstream bugs)

### Options Considered

1. **Infrastructure-Only (WAF/Load Balancer)**
2. **Application-Level with HTTP 429**
3. **Application-Level with Fail-Open (DEGRADED mode)**
4. **Hybrid Approach**

## Decision

**We will use a Hybrid Approach: Infrastructure rate limiting at the edge + Application-level load shedding with fail-open semantics.**

### Layer 1: Infrastructure Rate Limiting

- WAF/API Gateway enforces hard limits per client/tenant
- Returns HTTP 429 for clearly abusive traffic patterns
- Protects against DDoS and bot attacks

### Layer 2: Application Load Shedding

- Implemented via `LoadSheddingFilter` with configurable concurrency limit
- When limit exceeded, requests are shed with **fail-open behavior**
- Decision returned: `APPROVE` with `mode: DEGRADED`, `error_code: LOAD_SHEDDING`

## Rationale

### Why Not HTTP 429 Only?

Returning HTTP 429 at the application level would block legitimate transactions during traffic spikes. For a payment authorization service:

- A blocked transaction = failed payment = lost revenue for merchant
- A false-approved transaction = potential fraud = chargeback (recoverable)

The **cost of blocking legitimate transactions exceeds the cost of temporary fraud exposure**.

### Why Not Infrastructure-Only?

Pure infrastructure rate limiting:

- Cannot make intelligent decisions about request priority
- Applies same limits to all clients regardless of context
- Doesn't provide graceful degradation with business context

### Why Fail-Open?

Consistent with [ADR-0002: AUTH Fail-Open Default Approve](./0002-AUTH-fail-open-default-approve.md):

1. **Business Impact**: Blocking transactions has immediate, certain revenue impact
2. **Fraud Recovery**: Fraudulent transactions can be disputed/charged back
3. **Monitoring**: Elevated DEGRADED rate triggers alerts for investigation
4. **SLOs**: Fail-open maintains availability SLO even under stress

## Implementation

### Load Shedding Filter

```java
@Provider
@Priority(Priorities.AUTHENTICATION - 100) // Run early
public class LoadSheddingFilter implements ContainerRequestFilter {

    private final Semaphore permits;

    @ConfigProperty(name = "app.load-shedding.max-concurrent", defaultValue = "100")
    int maxConcurrent;

    @PostConstruct
    void init() {
        permits = new Semaphore(maxConcurrent);
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!permits.tryAcquire()) {
            // Shed load with fail-open response
            ctx.abortWith(Response.ok(Decision.degraded("LOAD_SHEDDING")).build());
        }
    }
}
```

### Response Format

When load shedding triggers:

```json
{
  "decision": "APPROVE",
  "mode": "DEGRADED",
  "error_code": "LOAD_SHEDDING",
  "matched_rules": [],
  "evaluation_time_ms": 0,
  "message": "Request shed due to capacity limits"
}
```

### Metrics

- `load_shedding_total{result="shed|processed"}` - Counter
- `concurrent_requests` - Gauge
- `decision_engine_mode{mode="DEGRADED"}` - Gauge

### Alerting

| Metric | Threshold | Alert |
|--------|-----------|-------|
| Load shed rate | > 1% for 5 min | P2 - Scale investigation |
| Load shed rate | > 10% for 2 min | P1 - Immediate scaling |
| Concurrent requests | > 80% of limit | P3 - Capacity warning |

## Configuration

```yaml
app:
  load-shedding:
    enabled: true
    max-concurrent: 100  # Per instance

# With 10 instances = 1000 concurrent capacity
# At 15ms P95 latency = ~66 TPS per instance = 660 TPS total
# Scale to handle 10k TPS = ~150 instances or optimize latency
```

## Consequences

### Positive

- Maintains availability during traffic spikes
- Consistent with existing fail-open philosophy
- Provides clear signal for capacity planning
- Protects service from cascading failures

### Negative

- Brief fraud exposure during load shedding events
- Requires careful monitoring and alerting
- May mask upstream issues if too permissive

### Neutral

- Requires coordination with infrastructure team for WAF rules
- Need to tune limits based on actual traffic patterns

## Related Decisions

- [ADR-0002: AUTH Fail-Open Default Approve](./0002-AUTH-fail-open-default-approve.md)
- [ADR-0003: HTTP 200 In-Band Fail-Open](./0003-http-200-inband-fail-open.md)
- [ADR-0005: MONITORING Redis Failure Semantics](./0005-MONITORING-redis-failure-semantics.md)

## References

- [Google SRE Book - Load Shedding](https://sre.google/sre-book/addressing-cascading-failures/)
- [AWS Well-Architected - Throttling](https://docs.aws.amazon.com/wellarchitected/latest/reliability-pillar/design-interactions-in-a-distributed-system-to-mitigate-or-withstand-failures.html)
