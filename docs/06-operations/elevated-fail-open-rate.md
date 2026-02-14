# Runbook: Elevated Fail-Open Rate

**Severity:** P1 - High
**Service:** card-fraud-rule-engine
**Component:** Rule Evaluation
**Last Updated:** 2026-01-24

---

## Symptoms

- **Alerts:**
  - `FailOpenRateHigh` alert firing
  - `DegradedModeActive` alert firing

- **Metrics:**
  - `fraud_engine_fail_open_total` rising rapidly
  - `decision_engine_mode{mode="FAIL_OPEN"}` gauge increasing
  - `decision_engine_mode{mode="DEGRADED"}` gauge increasing
  - AUTH approval rate unusually high

- **Logs:**
  - `WARN [RuleEvaluator] Evaluation error, defaulting to APPROVE (fail-open)`
  - `ERROR [RulesetLoader] Failed to load ruleset`
  - Various error codes in `engine_error_code` field

- **User-Visible Impact:**
  - Fraud detection effectiveness reduced
  - Transactions that should be declined may be approved
  - Business analytics may show anomalous approval patterns

---

## Impact

| Severity | Description |
|----------|-------------|
| **Financial** | Increased fraud exposure due to bypassed rules |
| **Compliance** | Potential regulatory concerns if sustained |
| **Data** | Decision data may be incomplete (missing velocity info) |

**Note:** Fail-open is by design for AUTH to ensure transaction availability. Short spikes are acceptable, but sustained high rates require investigation.

---

## Diagnosis

### 1. Identify Dominant Error Code

```bash
# Check error code distribution
curl -s http://localhost:8081/q/metrics | grep engine_error_code

# Common error codes:
# - REDIS_UNAVAILABLE: Redis connectivity issues
# - RULESET_NOT_LOADED: Ruleset loading failed
# - EVALUATION_ERROR: Rule evaluation exception
# - LOAD_SHEDDING: Request rejected due to overload
```

### 2. Check Dependency Health

```bash
# Redis
redis-cli -h $REDIS_HOST ping

# MinIO/S3 (ruleset storage)
aws s3 ls s3://fraud-gov-artifacts/rulesets/ --endpoint-url $S3_ENDPOINT_URL

# Check Quarkus health endpoints
curl -s http://localhost:8081/q/health | jq
```

### 3. Review Recent Changes

```bash
# Check recent deployments
kubectl get events -n fraud-engine --sort-by='.lastTimestamp' | tail -20

# Check config changes
doppler changelog --project=card-fraud-rule-engine --config=local
```

### 4. Check Resource Utilization

```bash
# CPU/Memory
kubectl top pods -n fraud-engine

# Connection pools
curl -s http://localhost:8081/q/metrics | grep pool
```

---

## Resolution

### By Error Code

#### REDIS_UNAVAILABLE
See [Redis Outage Runbook](./redis-outage.md)

#### RULESET_NOT_LOADED

```bash
# Check ruleset status
curl http://localhost:8081/v1/manage/rulesets/status

# Force reload
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey": "CARD_AUTH", "version": "latest"}'
```

#### EVALUATION_ERROR

1. Check logs for stack traces
2. Review recently deployed ruleset changes
3. Rollback ruleset if needed

#### LOAD_SHEDDING

```bash
# Scale up replicas
kubectl scale deployment fraud-engine --replicas=5 -n fraud-engine

# Or increase concurrency limit
kubectl set env deployment/fraud-engine MAX_CONCURRENT_REQUESTS=200 -n fraud-engine
```

### General Steps

1. **Stabilize the system:**
   - Scale up if load-related
   - Restart unhealthy pods
   - Switch to backup Redis if available

2. **Investigate root cause:**
   - Review logs and metrics
   - Check recent changes

3. **Communicate:**
   - Update status page if customer-facing
   - Notify stakeholders of elevated risk

---

## Prevention

1. **Monitoring:**
   - Alert on fail-open rate > 1% for > 5 minutes
   - Monitor individual error code rates

2. **Capacity Planning:**
   - Right-size Redis and engine pods
   - Implement auto-scaling policies

3. **Testing:**
   - Load test with realistic traffic
   - Chaos testing for failure scenarios

4. **Deployment:**
   - Canary deployments for ruleset changes
   - Gradual rollouts for engine updates

---

## Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | On-call SRE | Initial triage, scaling |
| L2 | Platform Team | Infrastructure issues |
| L3 | Fraud Engineering | Code/ruleset issues |

**Escalate to L2 if:**
- Infrastructure issues suspected
- Unable to scale or restart services

**Escalate to L3 if:**
- Ruleset content issues
- Code bugs suspected
- Fail-open rate sustained > 30 minutes

---

## How to Reproduce

### Test Scenario 1: Redis Outage

```bash
# Simulate Redis failure
docker stop card-fraud-rule-engine-redis

# Send transactions
for i in {1..20}; do
  curl -X POST http://localhost:8081/v1/evaluate/auth \
    -H "Content-Type: application/json" \
    -d '{"transaction_id":"test-'$i'","card_hash":"test-card-1","amount":50.00,"currency":"USD"}'
done

# Check fail-open rate increased
curl -s http://localhost:8081/q/metrics | grep "decision_engine_mode.*FAIL_OPEN"
```

### Test Scenario 2: Ruleset Unavailable

```bash
# Force ruleset unload (internal API)
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH","version":"nonexistent"}'

# Transactions should fail-open
```

### Test Scenario 3: Evaluation Error

```bash
# Deploy malformed ruleset (causes exceptions)
# Send transactions with fields that trigger the bug
```

---

## How to Verify Fix

### 1. Verify Fail-Open Rate Normalized

```bash
# Check fail-open rate over 5 minutes
curl -s http://localhost:8081/q/metrics | grep "decision_engine_mode.*FAIL_OPEN"
# Expected: rate < 1% of total decisions

# Check engine mode distribution
curl -s http://localhost:8081/q/metrics | grep "decision_engine_mode"
# Expected: mode="NORMAL" for >99% of decisions
```

### 2. Verify Error Codes Resolved

```bash
# Check error code distribution
curl -s http://localhost:8081/q/metrics | grep "engine_error_code"
# Expected: REDIS_UNAVAILABLE, RULESET_NOT_LOADED should not increase

# Check recent errors
grep "fail-open\|defaulting to APPROVE" /var/log/fraud-engine/app.log
# Expected: No recent entries
```

### 3. Verify Dependency Health

```bash
# Redis healthy
redis-cli -h $REDIS_HOST ping
# Expected: PONG

# Rulesets loaded
curl -s http://localhost:8081/v1/manage/rulesets/status | jq
# Expected: All rulesets show loaded status

# Circuit breakers closed
curl -s http://localhost:8081/q/metrics | grep "circuit_breaker_state"
# Expected: state=closed for all
```

### 4. Verify Decision Quality

```bash
# Send test transactions
curl -X POST http://localhost:8081/v1/evaluate/auth \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"verify-fix-001","card_hash":"verify-card","amount":99999.00,"currency":"USD","merchant_category_code":"7995"}'

# Response should be DECLINE (not APPROVE due to fail-open)
# Check response: decision="DECLINE", engine_mode="NORMAL"
```

---

## Alerting Configuration

### Prometheus Rules

```yaml
groups:
  - name: fail-open-alerts
    rules:
      - alert: FailOpenRateHigh
        expr: |
          sum(rate(decision_engine_mode_total{mode="FAIL_OPEN"}[5m])) /
          sum(rate(decision_engine_mode_total[5m])) > 0.01
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Elevated fail-open rate"
          description: "Fail-open rate at {{ $value | humanizePercentage }} (threshold: 1%)"

      - alert: FailOpenRateCritical
        expr: |
          sum(rate(decision_engine_mode_total{mode="FAIL_OPEN"}[5m])) /
          sum(rate(decision_engine_mode_total[5m])) > 0.05
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "CRITICAL: Very high fail-open rate"
          description: "Fail-open rate at {{ $value | humanizePercentage }} (threshold: 5%)"

      - alert: DegradedModeActive
        expr: decision_engine_mode{mode="DEGRADED"} == 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Engine operating in DEGRADED mode"
          description: "Engine {{ $labels.pod }} is in degraded mode"

      - alert: ErrorCodeSpike
        expr: increase(engine_error_code_total[5m]) > 100
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Error code spike detected"
          description: "{{ $labels.error_code }} errors increasing rapidly"
```

### Datadog Monitors

```json
{
  "name": "Fail-Open Rate Monitor",
  "type": "metric alert",
  "query": "avg(last_5m):sum:decision_engine_mode_total.mode{FAIL_OPEN} / sum:decision_engine_mode_total * 100 > 1",
  "message": "Fail-open rate exceeded 1%. Investigate dependency health.",
  "tags": ["service:card-fraud-rule-engine", "component:decision-engine"],
  "priority": 2
}
```

---

## Related Documentation

- [Redis Outage Runbook](./redis-outage.md)
- [Ruleset Reload Loop Runbook](./ruleset-reload-loop.md)
- [SLOs Document](../06-operations/slos.md)
