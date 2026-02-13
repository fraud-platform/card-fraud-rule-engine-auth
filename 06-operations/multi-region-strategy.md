# Multi-Region Deployment Strategy

**Version:** 1.0
**Last Updated:** 2026-01-24
**Status:** Planning

## Overview

This document outlines the strategy for deploying the card-fraud-rule-engine across multiple geographic regions to achieve:

1. **Low Latency**: Sub-15ms P95 for geographically distributed clients
2. **High Availability**: Survive single-region failures
3. **Data Consistency**: Consistent fraud detection across regions
4. **Compliance**: Data residency requirements for certain markets

## Architecture

### Deployment Topology

```
                    ┌─────────────────────────────────────┐
                    │        Global Load Balancer         │
                    │     (Latency-based routing)         │
                    └─────────────┬───────────────────────┘
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                         │                         │
        ▼                         ▼                         ▼
┌───────────────┐       ┌───────────────┐       ┌───────────────┐
│   US-EAST     │       │   EU-WEST     │       │   APAC        │
│               │       │               │       │               │
│ ┌───────────┐ │       │ ┌───────────┐ │       │ ┌───────────┐ │
│ │  Engine   │ │       │ │  Engine   │ │       │ │  Engine   │ │
│ │  Cluster  │ │       │ │  Cluster  │ │       │ │  Cluster  │ │
│ └─────┬─────┘ │       │ └─────┬─────┘ │       │ └─────┬─────┘ │
│       │       │       │       │       │       │       │       │
│ ┌─────▼─────┐ │       │ ┌─────▼─────┐ │       │ ┌─────▼─────┐ │
│ │   Redis   │ │       │ │   Redis   │ │       │ │   Redis   │ │
│ │  Cluster  │ │       │ │  Cluster  │ │       │ │  Cluster  │ │
│ └───────────┘ │       │ └───────────┘ │       │ └───────────┘ │
└───────────────┘       └───────────────┘       └───────────────┘
        │                         │                         │
        └─────────────────────────┼─────────────────────────┘
                                  │
                    ┌─────────────▼───────────────┐
                    │    Global S3 (Rulesets)     │
                    │   (Cross-region replicated) │
                    └─────────────────────────────┘
```

## Component Strategies

### Rule Engine (Stateless)

**Strategy: Active-Active in all regions**

- Each region runs independent engine clusters
- All clusters serve traffic simultaneously
- No cross-region communication required for request processing
- Horizontal scaling within each region based on load

**Configuration:**

```yaml
# Per-region Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fraud-engine
  labels:
    region: ${REGION}
spec:
  replicas: 10  # Scale per region
  template:
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: DoNotSchedule
```

### Redis (Velocity Counters)

**Strategy: Regional clusters with no cross-region sync**

Velocity counters are **region-local** by design:

1. **Latency**: Cross-region Redis sync would add unacceptable latency
2. **Consistency**: Eventual consistency is acceptable for velocity
3. **Failure Isolation**: Region failure doesn't affect other regions

**Trade-off**: A fraudster could potentially bypass velocity limits by distributing transactions across regions. Mitigation:

- Higher-level analytics detect cross-region patterns (async)
- Velocity thresholds account for regional split (~3x higher)
- Critical rules don't rely solely on velocity

**Configuration:**

```yaml
# Regional Redis cluster
redis:
  cluster:
    enabled: true
    nodes: 6  # 3 masters, 3 replicas
  persistence:
    enabled: true
    storageClass: regional-ssd
```

### Ruleset Storage (S3/MinIO)

**Strategy: Single source with cross-region replication**

- Primary bucket in US-EAST
- Cross-region replication to EU-WEST and APAC
- Each region reads from local replica
- ~15 minute replication lag acceptable for ruleset updates

**Configuration:**

```yaml
# S3 cross-region replication
s3:
  primary-bucket: fraud-gov-artifacts-us-east
  replicas:
    - fraud-gov-artifacts-eu-west
    - fraud-gov-artifacts-apac
  replication-rule:
    status: Enabled
    priority: 1
```

### Load Balancing

**Strategy: Latency-based routing with health checks**

- Global load balancer (AWS Global Accelerator, GCP Global LB, or Cloudflare)
- Routes to nearest healthy region
- Automatic failover on region health failure

**Health Check Configuration:**

```yaml
health-check:
  path: /q/health/ready
  interval: 10s
  threshold: 3  # failures before unhealthy
  timeout: 5s
```

## Failover Scenarios

### Scenario 1: Single Region Failure

**Detection**: Health checks fail for all pods in region
**Response**: Global LB routes traffic to next-nearest region
**Impact**: Increased latency for affected users (~50-150ms additional)
**Recovery**: Automatic when region recovers

### Scenario 2: Redis Cluster Failure (Single Region)

**Detection**: Circuit breaker opens for velocity checks
**Response**: Engine operates in DEGRADED mode (fail-open)
**Impact**: Velocity checks disabled for affected region
**Recovery**: Automatic when Redis recovers

### Scenario 3: Ruleset Replication Lag

**Detection**: Version mismatch alerts across regions
**Response**: Manual intervention if critical rules affected
**Impact**: Temporary rule inconsistency (usually acceptable)
**Recovery**: Automatic once replication catches up

## Data Residency

For compliance with data residency requirements (GDPR, etc.):

### Option A: Transaction Data Never Leaves Region

- Engine processes transaction locally
- Decision logged locally
- Aggregated analytics only cross-region

### Option B: Anonymized Cross-Region

- PII stripped before cross-region transfer
- Only aggregated metrics shared globally

**Current Approach**: Option A - all transaction data stays in region of origin.

## Deployment Process

### Rolling Update (Per Region)

```bash
# Update one region at a time
for region in us-east eu-west apac; do
  echo "Updating $region..."
  kubectl config use-context $region
  kubectl rollout restart deployment/fraud-engine
  kubectl rollout status deployment/fraud-engine --timeout=5m

  # Verify health before continuing
  ./scripts/verify-region-health.sh $region
done
```

### Ruleset Deployment

```bash
# Publish to primary, replication handles distribution
./scripts/publish-ruleset.sh --ruleset CARD_AUTH --version v5

# Wait for replication
sleep 900  # 15 minutes

# Verify all regions have new version
for region in us-east eu-west apac; do
  ./scripts/check-ruleset-version.sh $region CARD_AUTH
done
```

## Monitoring

### Global Dashboards

| Metric | Alert Threshold |
|--------|-----------------|
| Cross-region latency delta | > 100ms |
| Ruleset version drift | > 30 minutes |
| Regional traffic imbalance | > 40% deviation |
| Failed health checks | Any region down |

### Per-Region Metrics

- Request latency P50/P95/P99
- Error rate by type
- Velocity check success rate
- Ruleset version and age

## Cost Optimization

### Traffic Costs

- Minimize cross-region data transfer
- Use regional endpoints for S3
- Cache rulesets locally (already in-memory)

### Compute Costs

- Right-size per region based on traffic patterns
- Use spot/preemptible instances for non-critical capacity
- Auto-scaling based on regional demand

## Future Considerations

1. **Global Velocity**: Investigate low-latency cross-region velocity (CRDTs?)
2. **Edge Deployment**: Move evaluation closer to merchants (Cloudflare Workers?)
3. **Active-Passive Option**: For cost-sensitive deployments
4. **Multi-Cloud**: Reduce single-provider risk

## Related Documents

- [SLOs Document](../06-operations/slos.md)
- [Redis Outage Runbook](../06-operations/redis-outage.md)
- [Disaster Recovery Plan](./disaster-recovery.md)
