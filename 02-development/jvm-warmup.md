# JVM Warmup Optimization Guide

**Purpose:** Reduce cold-start latency through JVM warmup techniques.

**Last Updated:** 2026-02-02

---

## Problem: JVM Cold Start

When a Java application starts, it goes through several warmup phases:

| Phase | Duration | Impact |
|-------|----------|--------|
| **Class loading** | 1-2s | One-time cost |
| **Interpreter execution** | 5-10s | Slower execution |
| **C1 compilation** | 10-20s | Optimizing hot methods |
| **C2 compilation** | 20-30s | Peak performance |

**Result:** First 30 seconds have 2-3x higher latency than steady state.

---

## Impact on Fraud Detection

| Metric | Cold Start | Warm (30s+) | Difference |
|--------|-----------|-------------|------------|
| **P50 Latency** | 12ms | 4.8ms | +150% |
| **P95 Latency** | 18ms | 6.9ms | +160% |
| **P99 Latency** | 35ms | 8.2ms | +326% |

**Production Impact:** During deployments or pod scaling, new instances handle traffic with degraded latency for ~30 seconds.

---

## Solutions

### 1. CDS (Class Data Sharing) - Startup Time Reduction

**Benefit:** Reduces class loading overhead by ~20-30%

**Implementation:**

```bash
# Step 1: Create CDS archive (run once after build)
java -XX:ArchiveClassesAtExit=app-cds.jsa \
     -jar quarkus-run.jar \
     --quarkus.http.host=0.0.0.0 &

# Wait for warmup, then kill
sleep 30
kill %1

# Step 2: Use archive in production
java -XX:SharedArchiveFile=app-cds.jsa \
     -Xshare:auto \
     -jar quarkus-run.jar
```

**Trade-offs:**
- ✅ 20-30% faster startup
- ✅ Less memory (shared read-only pages)
- ❌ Archive is JDK-version specific
- ❌ Must be recreated after code changes

**Docker Configuration:**
```yaml
environment:
  - JAVA_CDS_OPTS=-XX:SharedArchiveFile=/app/quarkus-app/app-cds.jsa -Xshare:auto
```

---

### 2. Warmup Endpoint - Pre-traffic JIT Compilation

**Benefit:** Forces JIT compilation before serving real traffic

**Implementation:**

The engine includes a built-in warmup mechanism. Enable via environment variable:

```yaml
environment:
  - ENABLE_JVM_WARMUP=true
  - JVM_WARMUP_ITERATIONS=100
  - JVM_WARMUP_DELAY_SECONDS=5
```

**How it works:**

1. Application starts
2. Warmup runs `N` synthetic evaluation requests
3. Forces JIT compilation of hot paths
4. Then accepts real traffic

**Without warmup endpoint (manual script):**

```bash
# Warmup script for readiness probe
#!/bin/sh
WARMUP_URL="http://localhost:8081/v1/evaluate/warmup"
ITERATIONS=100

echo "Starting JVM warmup..."
for i in $(seq 1 $ITERATIONS); do
    curl -s -X POST "$WARMUP_URL" \
         -H "Content-Type: application/json" \
         -d '{"transaction_id":"warmup","amount":100.00,"card_hash":"abc123"}' > /dev/null
done
echo "Warmup complete"
```

---

### 3. Quarkus AppCDS - Built-in CDS Support

**Benefit:** Quarkus-native CDS with better integration

**Implementation:**

```bash
# Build with CDS enabled
./mvnw clean package -Dquarkus.package.type=fast-jar \
                   -Dquarkus.app.cds=true

# Run (CDS archive created automatically)
java -jar target/quarkus-app/quarkus-run.jar
```

**Configuration (application.yaml):**

```yaml
quarkus:
  package:
    app-cds:
      enabled: true
```

---

### 4. Readiness Probe with Warmup

**Kubernetes Example:**

```yaml
readinessProbe:
  httpGet:
    path: /health
    port: 8081
  initialDelaySeconds: 30   # Allow warmup period
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3

# Or use warmup endpoint
readinessProbe:
  exec:
    command:
    - sh
    - -c
    - |
      # Warmup then check health
      for i in $(seq 1 50); do
        curl -s http://localhost:8081/v1/evaluate/warmup > /dev/null
      done
      curl -s http://localhost:8081/health
  initialDelaySeconds: 5
  periodSeconds: 10
```

---

## Warmup Benchmarks

| Technique | Startup Time | P50 after 30s | Complexity |
|-----------|-------------|---------------|------------|
| **None (baseline)** | 8s | 4.8ms | - |
| **CDS only** | 5s (-40%) | 4.8ms | Low |
| **Warmup endpoint** | 8s | 4.8ms (from start) | Medium |
| **CDS + Warmup** | 5s | 4.8ms (from start) | Medium |

---

## Recommendation

### For Production Deployments

1. **Enable CDS** - Easy win, no downside
2. **Configure readiness probe delay** - 30s initial delay
3. **Use gradual rollout** - Don't replace all pods at once

### For Auto-scaling

1. **Pre-warm instances** - Create instances before traffic spike
2. **Warmup endpoint** - Force compilation before adding to pool
3. **Minimum instances** - Keep some warm instances alive

---

## Implementation: Docker Compose

```yaml
services:
  rule-engine:
    image: card-fraud-rule-engine:latest
    environment:
      # Enable CDS
      - JAVA_CDS_OPTS=-XX:SharedArchiveFile=/app/quarkus-app/app-cds.jsa -Xshare:auto
      # Enable warmup
      - ENABLE_JVM_WARMUP=true
      - JVM_WARMUP_ITERATIONS=100
    healthcheck:
      test: ["CMD", "wget", "--spider", "http://localhost:8081/health"]
      interval: 10s
      timeout: 3s
      start_period: 40s  # Allow time for warmup
      retries: 3
```

---

## Implementation: Kubernetes

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: jvm-warmup-config
data:
  warmup.sh: |
    #!/bin/sh
    echo "Starting JVM warmup..."
    for i in $(seq 1 100); do
      curl -s -X POST http://localhost:8081/v1/evaluate/warmup \
           -H "Content-Type: application/json" \
           -d '{"transaction_id":"warmup","amount":100.00}' > /dev/null
    done
    echo "Warmup complete"

---
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: rule-engine
    image: card-fraud-rule-engine:latest
    env:
    - name: JAVA_CDS_OPTS
      value: "-XX:SharedArchiveFile=/app/quarkus-app/app-cds.jsa -Xshare:auto"
    lifecycle:
      postStart:
        exec:
          command: ["/bin/sh", "-c", "/scripts/warmup.sh"]
    readinessProbe:
      httpGet:
        path: /health
        port: 8081
      initialDelaySeconds: 30
      periodSeconds: 5
```

---

## Monitoring Warmup

### Key Metrics

| Metric | Tool | Alert Threshold |
|--------|------|----------------|
| **Startup time** | Container logs | > 15s |
| **P50 latency (first minute)** | Load testing | > 2x steady state |
| **P99 latency (first minute)** | Load testing | > 50ms |
| **GC during warmup** | GC logs | High GC expected |

### Validation Command

```bash
# Check warmup effectiveness
for i in {1..60}; do
  echo "Request $i:"
  curl -X POST http://localhost:8081/v1/evaluate/auth \
       -H "Content-Type: application/json" \
       -d @test-transaction.json \
       -w "\nTime: %{time_total}s\n"
  sleep 1
done
```

---

## Troubleshooting

### CDS Archive Not Found

**Error:** `Unable to use shared archive app-cds.jsa`

**Solution:**
1. Create archive first (see CDS section above)
2. Or disable CDS: `unset JAVA_CDS_OPTS`

### Warmup Not Working

**Symptoms:** High latency persists after warmup

**Solutions:**
1. Increase iterations: `JVM_WARMUP_ITERATIONS=200`
2. Check warmup endpoint is accessible
3. Verify JIT compilation: `-XX:+PrintCompilation`

### Pods Killed During Warmup

**Error:** Pod OOMKilled during startup

**Solution:**
1. Increase memory request
2. Reduce warmup iterations
3. Use `initialDelaySeconds` in readiness probe

---

## References

- [Class Data Sharing (Oracle)](https://docs.oracle.com/en/java/javase/21/vm/class-data-sharing.html)
- [JIT Compilation (OpenJDK)](https://openjdk.org/projects/code-tools/jc/)
- [Quarkus CDS Guide](https://quarkus.io/guides/cds)

---

**End of Document**
