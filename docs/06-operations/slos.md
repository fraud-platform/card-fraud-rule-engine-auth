# Service Level Objectives (SLOs)

> **Project:** Card Fraud Rule Engine
> **Version:** 1.0
> **Last Updated:** 2026-01-31

---



| Mode | P50 (Median) | Overhead |
|------|--------------|----------|
| No-auth (dev mode) | 4.8ms | - |


**Optimization Opportunity:** Future optimization could:
1. Batch token validation (validate once per token, cache the claims)
4. Pre-validate and cache claims in `ScopeValidator` with TTL


---

---

## Overview

This document defines the Service Level Objectives (SLOs) for the Card Fraud Rule Engine. These are formal commitments to service quality that drive engineering priorities and operational decisions.

---

## Performance SLOs

### Latency Targets

| Percentile | Target | Notes |
|------------|--------|-------|
| **P50** | **< 5ms** | Measured in no-auth mode (dev/test) |
| P95 | < 15ms | Applies to all modes |
| P99 | < 30ms | Applies to all modes |


**Measurement:**
- Measured from HTTP request received to HTTP response sent
- Includes all rule evaluation, Redis operations, and response building
- Excludes network latency outside the service

**Note on Development vs Production Latency:**
- Development testing with Docker containers shows 4-7ms overhead due to Docker NAT
- Production Kubernetes environments eliminate this overhead
- Expected improvement in production: 2-4ms reduction in P50 latency

**Alerting Thresholds:**
- P95 > 20ms for 5 minutes → **WARNING**
- P95 > 30ms for 2 minutes → **CRITICAL**

---

### Throughput Target

| Metric | Target |
|--------|--------|
| **Sustained TPS** | 10,000+ transactions/second |
| **Peak Burst** | 15,000 TPS for 5 minutes |

**CPU Utilization @ 10k TPS:** < 50%

---

## Availability SLOs

| Metric | Target |
|--------|--------|
| **Uptime** | 99.9% (43.8 minutes/month downtime allowed) |
| **Error Rate** | < 0.1% (includes only 5xx errors) |

**Note:** 4xx errors (client errors) do not count against availability SLO.

---

## Fail-Open Behavior

Per ADR-0002, the engine follows **fail-open semantics**:

| Scenario | Behavior |
|----------|----------|
| Redis unavailable | Skip velocity, return APPROVE with `FAIL_OPEN` mode |
| Ruleset not loaded | Return APPROVE with `FAIL_OPEN` mode |
| Evaluation timeout | Return APPROVE with `FAIL_OPEN` mode |
| Any internal error | Return APPROVE with `FAIL_OPEN` mode |

**Fail-open rate is monitored:** If > 1% of requests are FAIL_OPEN, trigger WARNING alert.

---

## Error Budget

### Monthly Budget Calculation

| SLO | Target | Monthly Budget |
|-----|--------|----------------|
| Availability | 99.9% | 43.8 minutes |
| P95 Latency | < 15ms | See latency budget |

### Latency Error Budget

Latency error budget is calculated as "bad minutes":
- Minutes where P95 > 20ms: Count toward budget
- Budget: 30 minutes per month

### Budget Consumption

| Incident Type | Cost |
|---------------|------|
| 1 minute downtime (full outage) | 1 minute |
| 1 minute degraded (50% error rate) | 30 seconds |
| 1 minute P95 > 20ms | 1 minute |
| 1 minute P95 > 30ms | 5 minutes (multiplier) |

---

## Monitoring

### Metrics to Track

1. **Request Latency** - Histogram with p50, p95, p99
2. **Request Rate** - TPS by endpoint
3. **Error Rate** - 5xx errors as percentage
4. **Fail-Open Rate** - Requests with engine_mode=FAIL_OPEN
5. **CPU Utilization** - At current load
6. **Redis Availability** - Up/down percentage

### Dashboards

Required dashboards:
1. **Service Health** - Latency, throughput, errors
2. **Resource Usage** - CPU, memory, GC
3. **Fail-Open Tracking** - Rate and reasons

---

## Exclusions

The following are excluded from SLO calculations:

1. **Planned maintenance** - Pre-announced maintenance windows
2. **Client errors** - 4xx responses (invalid requests, auth failures)
4. **Load testing** - Automated load test traffic
5. **Development environment** - Docker NAT overhead in dev/test environments

---

## Local Development Testing

When testing locally with Docker containers, the following overhead applies:

| Environment | Expected P50 | Expected P95 |
|-------------|--------------|--------------|
| Development (Docker NAT) | 6-8ms | 8-10ms |
| Production (Kubernetes) | 4-5ms | 6-8ms |

**Development targets for local testing:**
- P50: < 10ms (relaxed due to Docker NAT)
- P95: < 15ms (same as production)
- P99: < 30ms (same as production)

See `docs/SESSION_NOTES.md` for local testing procedures.

---

## Review Schedule

| Frequency | Activity |
|-----------|----------|
| Weekly | Review error budget consumption |
| Monthly | Review SLO achievement, adjust targets if needed |
| Quarterly | Business review of SLO targets |

---

**End of Document**
