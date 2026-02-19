# GC Optimization Guide

**Purpose:** Guide for selecting and configuring the optimal garbage collector for the Card Fraud Rule Engine.

**Last Updated:** 2026-02-02

---

## Overview

The Card Fraud Rule Engine is a low-latency service where consistent P99 performance matters more than peak throughput. This guide helps select the optimal GC for your deployment scenario.

---

## GC Options Comparison

| GC | Pause Time | Throughput | Memory Overhead | Best For | Java Version |
|----|-----------|------------|-----------------|----------|--------------|
| **G1GC** (default) | 10-100ms | High | Low | General purpose, balanced | 9+ |
| **ZGC** | <1ms (sub-ms) | Medium | Low | Consistent P99 latency | 17+ (ZGen: 21+) |
| **Shenandoah** | <1ms (sub-ms) | Medium | Medium | Consistent P99 latency | 12+ |

### Key Metrics for Fraud Detection

| Metric | Target | Impact |
|--------|--------|--------|
| **P50 Latency** | < 5ms | User experience |
| **P95 Latency** | < 15ms | SLA compliance |
| **P99 Latency** | < 30ms | Critical - GC pauses directly impact |
| **TPS** | 10,000+ | Peak load handling |

**GC Pause Impact:** A 50ms GC pause can cause P99 spikes to 50ms+, even if average latency is 5ms.

---

## Recommendation by Use Case

### 1. Production (Default): G1GC

**Use when:**
- You need balanced throughput and latency
- Memory is constrained (< 1GB heap)
- You want the battle-tested default

**Configuration:**
```bash
JAVA_GC_OPTS="-XX:+UseG1GC -XX:+UseStringDeduplication"
```

**Trade-offs:**
- ✅ Best throughput
- ✅ Lowest memory overhead
- ✅ Most battle-tested
- ❌ Higher pause times (10-100ms)
- ❌ P99 may spike during GC

---

### 2. Low-Latency Production: ZGC (Recommended for P99)

**Use when:**
- Consistent P99 latency is critical
- Heap size > 1GB (ZGC scales better)
- Running Java 25+

**Configuration:**
```bash
JAVA_GC_OPTS="-XX:+UseZGC -XX:+ZGenerational"
```

**Trade-offs:**
- ✅ Sub-millisecond pauses
- ✅ Consistent P99 latency
- ✅ Scales to large heaps
- ❌ Slightly lower throughput (~5-10%)
- ❌ More CPU usage during concurrent phases

**When to choose ZGC:**
- P99 latency SLA is strict (< 20ms)
- You see P99 spikes with G1GC
- Heap size is 2GB or more

---

### 3. Alternative Low-Latency: Shenandoah

**Use when:**
- ZGC is not available (older Java versions)
- You want an alternative low-pause GC

**Configuration:**
```bash
JAVA_GC_OPTS="-XX:+UseShenandoahGC"
```

**Trade-offs:**
- ✅ Sub-millisecond pauses
- ✅ Works on older Java versions
- ❌ Slightly higher memory overhead
- ❌ Less battle-tested than ZGC

---

## Configuration Examples

### Docker Compose (Default G1GC)

```yaml
services:
  rule-engine:
    image: card-fraud-rule-engine:latest
    environment:
      - JAVA_GC_OPTS=-XX:+UseG1GC -XX:+UseStringDeduplication
```

### Docker Compose (ZGC for Low Latency)

```yaml
services:
  rule-engine:
    image: card-fraud-rule-engine:latest
    environment:
      - JAVA_GC_OPTS=-XX:+UseZGC -XX:+ZGenerational
    deploy:
      resources:
        limits:
          memory: 1G  # ZGC benefits from larger heap
```

### Kubernetes (ZGC)

```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: rule-engine
    image: card-fraud-rule-engine:latest
    env:
    - name: JAVA_GC_OPTS
      value: "-XX:+UseZGC -XX:+ZGenerational"
    resources:
      limits:
        memory: "1Gi"
      requests:
        memory: "512Mi"
```

---

## Benchmark Results (Expected)

Based on similar workloads (10K TPS, 1GB heap):

| GC | P50 | P95 | P99 | GC Pauses | Throughput |
|----|-----|-----|-----|-----------|------------|
| **G1GC** | 4.8ms | 6.9ms | 25ms | 10-50ms | 10,500 TPS |
| **ZGC** | 5.0ms | 7.5ms | **9ms** | <1ms | 9,800 TPS |
| **Shenandoah** | 5.1ms | 7.8ms | **10ms** | <1ms | 9,700 TPS |

**Note:** ZGC/Shenandoah trade ~5-7% throughput for 60-70% better P99 latency.

---

## Monitoring GC Performance

### Key Metrics to Watch

```bash
# Enable GC logging (add to JAVA_OPTS)
-XX:+PrintGC -XX:+PrintGCDetails -XX:+PrintGCTimeStamps

# Or for Java 25+
-Xlog:gc*:file=/logs/gc.log:time,level,tags
```

### Metrics to Collect

| Metric | G1GC | ZGC | Shenandoah |
|--------|------|-----|------------|
| **Pause time** | Explicit | Explicit | Explicit |
| **Heap usage** | Important | Less critical | Less critical |
| **CPU usage** | Baseline | +5-10% | +5-15% |

---

## Migration Guide

### From G1GC to ZGC

1. **Verify Java version:**
   ```bash
   java -version  # Must be 21+ for ZGenerational
   ```

2. **Update environment variable:**
   ```bash
   export JAVA_GC_OPTS="-XX:+UseZGC -XX:+ZGenerational"
   ```

3. **Run with load testing:**
   ```bash
   # Run load test and compare P99
   ```

4. **Monitor for 1-2 weeks:**
   - Check P99 latency
   - Monitor CPU usage
   - Verify heap size is adequate

---

## Troubleshooting

### ZGC: "VM option 'UseZGC' not available"

**Cause:** Java version too old (< 17 for ZGC, < 21 for ZGenerational)

**Solution:** Upgrade to Java 25+

### High CPU with ZGC/Shenandoah

**Cause:** Concurrent GC phases use more CPU

**Solution:** This is expected. Trade lower latency for higher CPU.

### Out of Memory with ZGC

**Cause:** ZGC needs slightly more headroom

**Solution:** Increase heap by 10-20%

---

## Decision Matrix

| Situation | Recommended GC |
|-----------|----------------|
| **Default deployment** | G1GC |
| **P99 latency SLA strict (< 20ms)** | ZGC |
| **Large heap (> 2GB)** | ZGC |
| **Limited CPU** | G1GC |
| **Memory constrained (< 512MB)** | G1GC |
| **Java 25+ available** | ZGC (recommended) |
| **Older Java version** | G1GC or Shenandoah |

---

## References

- [ZGC Documentation](https://openjdk.org/jeps/333)
- [Shenandoah Documentation](https://wiki.openjdk.org/display/Shenandoah)
- [G1GC Documentation](https://docs.oracle.com/en/java/javase/21/gctuning/garbage-first-garbage-collector.html)

---

**End of Document**
