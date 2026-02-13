# JAR-Based Load Testing Guide

**Last Updated:** 2026-02-07

## Critical: Why JAR-Based Testing?

**DO NOT use `mvn quarkus:dev` for load testing!**

Both `uv run doppler-local` and `uv run doppler-load-test` run `mvn quarkus:dev`, which includes:
- **JaCoCo bytecode instrumentation** (10-50x method call overhead)
- **Live coding / hot reload** (file watching overhead)
- **DEBUG logging** in dev profile (thousands of log lines/second)

**Measured impact:**
- Single AUTH request: 5-7ms TTFB (fast)
- Under load with dev mode: 280ms P50, 470ms P95, 590ms P99 (50x slower)
- Docker vs Native gave identical bad results, proving overhead is dev mode, not Docker

## Packaging the JAR

### Build Production JAR

```bash
# Build uber-jar (includes all dependencies)
doppler run --config local -- mvn package -DskipTests -Dquarkus.package.jar.type=uber-jar
```

**Output:** `target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar`

**Build time:** ~30-60 seconds

### Verify JAR

```bash
# Check JAR size (should be ~30-50MB)
ls -lh target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar
```

## Running JAR-Based Load Tests

### Prerequisites

1. **Start infrastructure:**
   ```bash
   cd C:\Users\kanna\github\card-fraud-platform
   doppler run -- uv run platform-up
   ```

2. **Verify infrastructure:**
   ```bash
   # Redis
   uv run redis-local-verify

   # Kafka (Redpanda)
   docker ps | grep redpanda

   # MinIO
   curl -s http://localhost:9000/minio/health/live
   ```


```bash
cd C:\Users\kanna\github\card-fraud-rule-engine

doppler run --config local -- \
java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar \
  -Dquarkus.profile=load-test
```

**Wait for:**
```
Listening on: http://0.0.0.0:8081
```

**Terminal 2 - Run load test:**
```bash
cd C:\Users\kanna\github\card-fraud-e2e-load-testing

uv run lt-run \
  --service rule-engine \
  --users=200 \
  --spawn-rate=20 \
  --run-time=2m \
  --scenario baseline \
  --headless
```

**Expected results:**
- AUTH P50: < 10ms (previously 280ms with dev mode)
- AUTH P95: < 15ms (previously 470ms with dev mode)
- AUTH P99: < 30ms (previously 590ms with dev mode)
- Total RPS: > 5,000 (previously ~455 with dev mode)
- 0% failures


```bash
cd C:\Users\kanna\github\card-fraud-rule-engine

doppler run --config local -- \
java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar \
  -Dquarkus.profile=load-test
```

**Wait for:**
```
Listening on: http://0.0.0.0:8081
```

```bash
cd C:\Users\kanna\github\card-fraud-e2e-load-testing

uv run lt-run \
  --service rule-engine \
  --users=200 \
  --spawn-rate=20 \
  --run-time=2m \
  --scenario baseline \
  --headless
```

**Status:** BLOCKED - Need to pass Doppler secrets to e2e harness process

## Load Test Configuration

### Load Shedding (DISABLED for load tests)

The `%load-test` profile automatically disables load shedding:

```yaml
"%load-test":
  app:
    load-shedding:
      enabled: false  # Measure true capacity without artificial limits
```

**Why disabled?**
- Default `max-concurrent: 100` would shed 50% of requests at 200 users
- Load shedding path still does blocking I/O (Redis XADD, Kafka await)
- Shedding doesn't reduce load, just returns DEGRADED responses

### Logging (WARN level for throughput)

```yaml
"%load-test":
  quarkus:
    log:
      level: WARN
      category:
        "com.fraud.engine":
          level: WARN  # Suppress hot-path logging
```

### Kafka Configuration

```yaml
mp:
  messaging:
    outgoing:
      decision-events:
        enable.idempotence: true
        acks: all
        max.in.flight.requests.per.connection: 5
        batch.size: 16384
        linger.ms: 5
        compression.type: lz4
        delivery.timeout.ms: 15000
```

**Note:** `max.in.flight.requests.per.connection: 5` can serialize concurrent Kafka sends. This is intentional for durability but may impact throughput under extreme load.

## Timeout Configuration

All blocking I/O operations have bounded timeouts:

### Redis Operations (Outbox)
- **XADD (append):** 5s timeout (configurable via `OUTBOX_REDIS_TIMEOUT_SECONDS`)
- **XREADGROUP (read):** `BLOCK` timeout + 5s buffer
- **XACK (acknowledge):** 5s timeout

### Kafka Operations
- **Publish (await):** 5s timeout (DecisionPublisher.java:91)
- **Delivery timeout:** 15s (application.yaml)

## Monitoring During Load Tests

### JVM Metrics

```bash
# CPU usage
docker stats card-fraud-rule-engine

# GC activity (if running with JMX enabled)
jconsole localhost:9010
```

### Redis Metrics

```bash
# Connection count
redis-cli -h localhost -p 6379 INFO clients

# Command latency
redis-cli -h localhost -p 6379 --latency

# Outbox stream depth
redis-cli -h localhost -p 6379 XLEN fraud:outbox
```

### Kafka Metrics

```bash
# Consumer lag (if applicable)
docker exec -it redpanda rpk topic describe fraud.card.decisions.v1
```

## Troubleshooting

### Issue: High latency despite JAR-based testing

**Check:**
1. Docker CPU limits: `docker stats` - increase if throttled
2. Redis connection pool: verify `REDIS_MAX_POOL_SIZE` is sufficient
3. Kafka batching: check `linger.ms` and `batch.size` settings
4. GC pauses: monitor GC logs

### Issue: Connection refused

**Fix:**
```bash
# Verify rule engine is running
curl -s http://localhost:8081/health

# Check firewall
netstat -an | grep 8081
```


**Fix:**
```bash
# This env var must be passed to the java process, not just in application.yaml

java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar
```

### Issue: DEGRADED responses

**Causes:**
1. Redis unavailable - check `uv run redis-local-verify`
2. Kafka unavailable - check `docker ps | grep redpanda`
3. Outbox timeout - increase `OUTBOX_REDIS_TIMEOUT_SECONDS`

## Performance Targets

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| AUTH P50 Latency | < 10ms | < 15ms |
| AUTH P95 Latency | < 15ms | < 30ms |
| AUTH P99 Latency | < 30ms | < 50ms |
| Throughput | > 10,000 TPS | > 5,000 TPS |
| Error Rate | < 0.1% | < 1% |
| FAIL_OPEN Rate | < 0.01% | < 0.1% |

## Next Steps After Baseline

1. **Profile with async-profiler:**
   ```bash
   java -agentpath:/path/to/libasyncProfiler.so=start,event=cpu,file=profile.html \
     -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar
   ```

2. **Run longer soak tests:**
   - Duration: 30-60 minutes
   - Monitor for memory leaks, GC pressure
   - Check for connection pool exhaustion

3. **Test failure modes:**
   - Redis outage (stop Redis mid-test)
   - Kafka outage (stop Redpanda mid-test)
   - Network latency injection

4. **Document SLA compliance:**
   - Update `load-testing-baseline.md` with final results
   - Capture baseline metrics for future regression testing

## Related Documents

- [Load Testing Baseline](./load-testing-baseline.md) - Results and analysis
- [Performance Tuning](../02-development/performance-tuning.md) - Optimization guide
- [SLOs](../06-operations/slos.md) - Service level objectives
