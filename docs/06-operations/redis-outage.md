# Runbook: Redis Outage

**Severity:** P1 - High
**Service:** card-fraud-rule-engine
**Component:** VelocityService (Redis) + Redis Streams Outbox (ADR-0014)
**Last Updated:** 2026-02-05

---

## Symptoms

- **Alerts:**
- `VelocityCheckFailure` alert firing
- `RedisConnectionTimeout` alert firing
- `CircuitBreakerOpen` alert for VelocityService
- `OutboxBacklogHigh` or `redis.pending.entries` growing (auth enqueues to Redis Streams)

- **Metrics:**
  - `velocity_check_errors_total` increasing rapidly
  - `redis_connection_pool_exhausted` > 0
- `decision_engine_mode{mode="DEGRADED"}` gauge = 1
- Increased `engine_mode=FAIL_OPEN` (AUTH) and/or `engine_mode=DEGRADED` (MONITORING)
- `redis.oldest.pending.age` rising; `redis.pending.entries` > threshold

- **Logs:**
  - `WARN [VelocityService] Velocity check circuit breaker open`
  - `ERROR [RedisDataSource] Connection refused`
  - `WARN [VelocityService] Velocity check failed for key: vel:*`

- **User-Visible Impact:**
  - Velocity limits are NOT being enforced
  - Transactions that should be declined/reviewed may be approved
  - Engine mode changes from NORMAL to DEGRADED

---

## Impact

| Severity | Description |
|----------|-------------|
| **Financial** | Velocity-based fraud detection disabled; potential for increased fraud losses |
| **Operational** | Engine operates in degraded mode with fail-open semantics; monitoring worker may stall if outbox unreachable |
| **Data** | Velocity counters not updated; outbox entries may fail to enqueue/ack; if Redis is down, AUTH rejects instead of losing events |

**Note:** The rule engine is designed to fail-open. AUTH transactions will still be processed with APPROVE as the default action when velocity checks fail.

---

## Diagnosis

### 1. Verify Redis Connectivity (velocity + streams)

```bash
# Check Redis container status
docker ps | grep redis

# Check Redis connectivity from engine pod
kubectl exec -it <engine-pod> -- redis-cli -h $REDIS_HOST ping

# Check Redis logs
docker logs card-fraud-rule-engine-redis --tail 100
```

### 2. Check Engine Metrics

```bash
# Check circuit breaker state
curl -s http://localhost:8081/q/metrics | grep circuit_breaker

# Check velocity error rate
curl -s http://localhost:8081/q/metrics | grep velocity_check_errors
```

### 3. Check Redis Health

```bash
# Redis memory usage
redis-cli INFO memory | grep used_memory_human

# Check stream depth
redis-cli XLEN fraud:outbox
redis-cli XINFO CONSUMERS fraud:outbox auth-monitoring-worker

# Redis connection count
redis-cli INFO clients | grep connected_clients

# Check for slow operations
redis-cli SLOWLOG GET 10
```

---

## Resolution

### Option A: Redis Container Restart (Docker)

```bash
# Restart Redis container
docker restart card-fraud-rule-engine-redis

# Verify Redis is healthy
docker exec card-fraud-rule-engine-redis redis-cli ping
```

### Option B: Redis Pod Restart (Kubernetes)

```bash
# Delete the Redis pod (StatefulSet will recreate it)
kubectl delete pod redis-0 -n fraud-engine

# Wait for pod to be ready
kubectl wait --for=condition=ready pod/redis-0 -n fraud-engine --timeout=60s
```

### Option C: Redis Cluster Failover

If using Redis Cluster or Sentinel:

```bash
# Trigger manual failover
redis-cli -h sentinel-host -p 26379 SENTINEL FAILOVER mymaster
```

### Post-Recovery Verification

1. **Verify Redis connectivity:**
   ```bash
   redis-cli -h $REDIS_HOST ping
   # Expected: PONG
   ```

2. **Verify circuit breaker closed:**
   ```bash
   curl -s http://localhost:8081/q/metrics | grep "circuit_breaker_state.*velocity"
   # Expected: state=closed
   ```

3. **Verify velocity checks working:**
   ```bash
   # Send test transaction and check logs
   grep "Velocity check:" /var/log/fraud-engine/app.log | tail -5
   ```

---

## Prevention

1. **Redis High Availability:**
   - Use Redis Sentinel or Cluster for automatic failover
   - Configure appropriate replicas (min 3 for production)
   - Enable AOF with `appendfsync everysec`, `min-replicas-to-write 1`, `min-replicas-max-lag 2` (required for outbox durability)

2. **Connection Pool Tuning:**
   - Monitor `redis_connection_pool_active` metric
   - Adjust pool size based on traffic patterns

3. **Circuit Breaker Monitoring:**
   - Alert when circuit breaker opens
   - Review failure thresholds periodically

4. **Memory Management:**
   - Set `maxmemory` appropriately
   - Configure `maxmemory-policy` to `allkeys-lru`
   - Monitor memory usage and set alerts at 80%

---

## Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | On-call SRE | Initial response, basic troubleshooting |
| L2 | Platform Team | Redis cluster issues, infrastructure |
| L3 | Fraud Engineering | Application-level issues, code changes |

**Escalate to L2 if:**
- Redis outage persists > 15 minutes after restart
- Cluster/Sentinel failover fails
- Data corruption suspected

**Escalate to L3 if:**
- Circuit breaker not closing after Redis recovery
- Velocity logic issues suspected
- Code changes required

---

## How to Reproduce

### Test Scenario 1: Redis Container Failure

```bash
# Simulate Redis container crash
docker restart card-fraud-rule-engine-redis

# During restart, observe velocity checks failing
# Engine should enter DEGRADED mode
```

### Test Scenario 2: Redis Connection Pool Exhaustion

```bash
# Open multiple connections to exhaust pool (in separate terminals)
for i in {1..50}; do
  redis-cli -h localhost -p 6379 PING &
done
wait

# Attempt transactions - should see pool exhaustion in logs
```

### Test Scenario 3: Network Partition

```bash
# Block Redis port
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Observe circuit breaker opening
# After timeout, observe FAIL_OPEN mode

# Restore
iptables -D INPUT -p tcp --dport 6379 -j DROP
```

---

## How to Verify Fix

### 1. Verify Redis Connectivity

```bash
# Test basic connectivity
redis-cli -h $REDIS_HOST ping
# Expected: PONG

# Test from engine pod
kubectl exec -it <engine-pod> -- redis-cli -h $REDIS_HOST ping
# Expected: PONG
```

### 2. Verify Circuit Breaker Closed

```bash
# Check circuit breaker state
curl -s http://localhost:8081/q/metrics | grep "circuit_breaker_state.*velocity"
# Expected: state=closed

# Check velocity error rate is zero
curl -s http://localhost:8081/q/metrics | grep velocity_check_errors_total
# Expected: No increase after recovery
```

### 3. Verify Velocity Checks Working

```bash
# Send test transactions
curl -X POST http://localhost:8081/v1/evaluate/auth \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"test-verify-001","card_hash":"test-card-1","amount":50.00,"currency":"USD","merchant_category_code":"5411","country_code":"US"}'

# Check logs for successful velocity check
grep "Velocity check passed" /var/log/fraud-engine/app.log | tail -5
```

### 4. Verify Engine Mode Normal

```bash
# Check engine mode metrics
curl -s http://localhost:8081/q/metrics | grep "decision_engine_mode"
# Expected: mode="NORMAL" (no FAIL_OPEN or DEGRADED)
```

---

## Alerting Configuration

### Prometheus Rules

```yaml
groups:
  - name: redis-outage-alerts
    rules:
      - alert: RedisConnectionFailure
        expr: velocity_check_errors_total > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Redis connection failures detected"
          description: "{{ $labels.pod }} experiencing Redis connectivity issues"

      - alert: CircuitBreakerOpen
        expr: circuit_breaker_state{component="velocity"} == 1
        for: 30s
        labels:
          severity: warning
        annotations:
          summary: "Velocity circuit breaker open"
          description: "Circuit breaker open for {{ $labels.pod }} - velocity checks bypassed"

      - alert: FailOpenModeActive
        expr: increase(decision_engine_mode_total{mode="FAIL_OPEN"}[5m]) > 100
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Engine operating in FAIL_OPEN mode"
          description: "Elevated fail-open rate detected"

      - alert: RedisMemoryUsageHigh
        expr: redis_memory_used_bytes / redis_memory_max_bytes > 0.8
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Redis memory usage high"
          description: "Redis at {{ $value | humanize1024 }}B / {{ $value | humanize1024 }}B"
```

### Datadog Monitors

```json
{
  "name": "Redis Connection Health",
  "type": "metric alert",
  "query": "avg(last_5m):avg:velocity_check_errors_total{service:card-fraud-rule-engine} > 10",
  "message": "Redis connection failures detected. Investigate immediately.",
  "tags": ["service:card-fraud-rule-engine", "component:redis"],
  "priority": 1
}
```

---

## Related Documentation

- [Redis Setup Guide](../01-setup/redis-setup.md)
- [SLOs Document](../06-operations/slos.md)
