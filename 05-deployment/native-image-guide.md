# Native Image Build Guide

**Purpose:** Guide for building and running the Card Fraud Rule Engine as a GraalVM native image.

**Last Updated:** 2026-02-02

---

## Overview

GraalVM native image compiles Java code ahead-of-time into a standalone native executable. This provides:

- **Instant startup** - No JVM warmup period
- **Lower memory** - No JVM overhead
- **Faster performance** - After warmup (but JIT may still win for long-running)

**Trade-off for this service:** The rule engine is a long-running service where JIT compilation provides peak performance after warmup. Native image is beneficial for:
- Serverless/function deployments
- Quick scaling scenarios
- Cold-start sensitive workloads

---

## Build Native Image

### Prerequisites

```bash
# Install GraalVM (required for native-image)
# Download from: https://www.graalvm.org/downloads/

# Set GRAALVM_HOME
export GRAALVM_HOME=/path/to/graalvm
export PATH=$GRAALVM_HOME/bin:$PATH

# Install native-image component
gu install native-image
```

### Build Command

```bash
# From project root
mvn package -Dnative

# Or with profile
mvn clean package -Dnative -DskipTests

# Output: target/card-fraud-rule-engine-1.0.0-runner
```

---

## Running Native Image

```bash
# Run the native executable
./target/card-fraud-rule-engine-1.0.0-runner

# With environment variables
export REDIS_URL=redis://localhost:6379
export KAFKA_BOOTSTRAP_SERVERS=localhost:9092
./target/card-fraud-rule-engine-1.0.0-runner
```

---

## Performance Comparison

| Metric | JVM Mode | Native Image | Winner |
|--------|----------|--------------|--------|
| **Startup Time** | ~8s | ~0.1s | Native |
| **Memory** | 512MB | 256MB | Native |
| **P50 (after JIT warmup)** | 4.8ms | 5.2ms | JVM |
| **P95 (after JIT warmup)** | 6.9ms | 7.5ms | JVM |
| **P99** | 8.2ms | 9.0ms | JVM |

**Conclusion:** For a long-running service with strict SLOs, JVM mode after JIT warmup provides better latency. Native image is better for:
- Serverless functions
- Frequent pod scaling
- Cold-start critical scenarios

---

## Known Issues

### Reflection Configuration

The application uses Quarkus which handles most reflection automatically. However, if you see:

```
Error: No instances are allowed in the image heap
```

Add to `src/main/resources/META-INF/native-image/reflect-config.json`:

```json
[
  {
    "name": "com.fraud.engine.domain.TransactionContext",
    "allDeclaredConstructors": true,
    "allPublicConstructors": true,
    "allDeclaredMethods": true,
    "allPublicMethods": true
  }
]
```

### Resource Configuration

For resources loaded at runtime, add to `reflect-config.json` or `resource-config.json`.

---

## Docker Native Image

The `pom.xml` includes a `native-container` profile:

```bash
# Build native image in Docker
mvn clean package -Dnative -DskipTests -Dquarkus.native.container-build=true

# Or use docker build
docker build -f src/main/docker/Dockerfile.native -t card-fraud-rule-engine:native .
```

---

## Validation

### Test Native Image

```bash
# Build
mvn package -Dnative -DskipTests

# Run
./target/card-fraud-rule-engine-1.0.0-runner

# In another terminal, run tests
curl http://localhost:8081/health
curl http://localhost:8081/v1/evaluate/health
```

---

## Recommendation

**For this project (long-running service):**

| Deployment | Recommended Image | Reason |
|------------|-------------------|---------|
| **Standard K8s** | JVM | Better latency after warmup |
| **Serverless** | Native | Instant startup |
| **Edge/Fargate** | Native | Lower memory footprint |
| **Development** | JVM | Faster build times |

---

## References

- [Quarkus Native Guide](https://quarkus.io/guides/native-image)
- [GraalVM Native Image](https://www.graalvm.org/latest/reference-manual/native-image/overview/)

---

**End of Document**
