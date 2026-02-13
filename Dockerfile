# =============================================================================
# Card Fraud Rule Engine - Production Dockerfile
# Multi-stage build: Maven builder → JRE Alpine runtime
#
# GraalVM native-image is NOT used here. The engine runs continuously and
# benefits from JIT warmup for peak throughput. Native-image would help
# cold-start latency (serverless) but is unnecessary for a long-running service.
#
# GC Selection via JAVA_GC_OPTS environment variable:
#   - G1GC (default):  Balanced for throughput and latency. Good for most workloads.
#   - ZGC:          Sub-millisecond pauses. Best for consistent P99 latency.
#   - Shenandoah:   Alternative low-pause GC. Similar to ZGC.
#
# JVM Warmup via JAVA_WARMUP_OPTS:
#   Set ENABLE_JVM_WARMUP=true to run warmup requests before accepting traffic
# =============================================================================

# Stage 1: Build with Maven
# =============================================================================
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /build

# Copy POM first for dependency layer caching
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build (skip tests — run separately in CI)
COPY src ./src
RUN mvn clean package -DskipTests -B

# =============================================================================
# Stage 2: Runtime - minimal JRE Alpine
# =============================================================================
FROM eclipse-temurin:21-jre-alpine

# Create non-root user (no packages needed — Alpine has wget via busybox)
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy Quarkus fast-jar from build stage and set ownership (single layer)
COPY --from=build --chown=appuser:appgroup /build/target/quarkus-app /app/quarkus-app

USER appuser

EXPOSE 8081

HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1

# JVM flags (use shell for environment variable expansion):
#   -XX:MaxRAMPercentage=75.0  — use up to 75% of container memory limit
#   ${JAVA_GC_OPTS}              — GC selection (defaults to G1GC below)
#   ${JAVA_CDS_OPTS}             — CDS archive for faster startup (optional)
#   ${JAVA_WARMUP_OPTS}          — Warmup settings (optional)
#   -Dquarkus.http.host=0.0.0.0  — bind to all interfaces
#
# GC Options (set JAVA_GC_OPTS env var to override):
#   G1GC (default):        "-XX:+UseG1GC -XX:+UseStringDeduplication"
#   ZGC (Java 21+):        "-XX:+UseZGC -XX:+ZGenerational"
#   Shenandoah (Java 21+): "-XX:+UseShenandoahGC"
#
# CDS Options (set JAVA_CDS_OPTS to enable):
#   "-XX:SharedArchiveFile=/app/quarkus-app/app-cds.jsa -Xshare:auto"
#
# Warmup Options (set ENABLE_JVM_WARMUP=true to run warmup):
#   See docs/JVM_WARMUP.md for details
ENTRYPOINT ["sh", "-c", \
    "java ${JAVA_GC_OPTS:--XX:+UseG1GC -XX:+UseStringDeduplication -XX:+AlwaysPreTouch} \
    ${JAVA_CDS_OPTS:-} \
    ${JAVA_JFR_OPTS:-} \
    -XX:MaxRAMPercentage=75.0 \
    -Dquarkus.http.host=0.0.0.0 \
    -DENABLE_JVM_WARMUP=${ENABLE_JVM_WARMUP:-false} \
    -jar quarkus-app/quarkus-run.jar"]
