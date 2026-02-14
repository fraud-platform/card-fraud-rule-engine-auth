# Artifact Retention Policy

> **Project:** Card Fraud Rule Engine
> **Version:** 1.0
> **Last Updated:** 2026-01-24

---

## Overview

This document defines the retention policy for ruleset artifacts stored in MinIO/S3.

---

## Retention Rules

### Active Retention

| Artifact Type | Retention Period |
|---------------|------------------|
| **Production rulesets** | 90 days in active storage |
| **Staging/Test rulesets** | 30 days in active storage |
| **Development rulesets** | 7 days in active storage |

### Minimum Version Retention

Regardless of time, always retain:
- **Last 10 versions** of each ruleset
- **Current production version** (indefinitely until replaced)
- **Previous production version** (for rollback capability)

---

## Version Lifecycle

```
┌──────────────┐
│  New Version │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Active Use   │ ← Current production
└──────┬───────┘
       │
       ▼ (when replaced)
┌──────────────┐
│ Previous     │ ← Keep for rollback (30 days)
└──────┬───────┘
       │
       ▼ (after 30 days OR 10 newer versions)
┌──────────────┐
│ Archive      │ ← Move to cold storage
└──────┬───────┘
       │
       ▼ (after 1 year)
┌──────────────┐
│ Delete       │
└──────────────┘
```

---

## Rollback Capability

### Hot-Rollback Window

**Duration:** 30 days after a new version is deployed

**Within this window:**
- Previous version remains in active storage
- Can be hot-swapped via `/v1/evaluate/rulesets/hotswap` endpoint
- Zero-downtime rollback

**After this window:**
- Version moved to archive (cold storage)
- Rollback requires restoring from archive (~5-10 minute delay)

---

## Archive Policy

### Cold Storage

| Condition | Action |
|-----------|--------|
| Version > 30 days old | Move to archive storage class |
| More than 10 versions exist | Keep only 10 most recent in active |
| 1 year old | Eligible for deletion |

### Archive Storage Class

- Use `GLACIER` or `DEEP_ARCHIVE` for S3
- Use `STANDARD_IA` (Infrequent Access) tier for MinIO
- Restore time: 5-10 minutes

---

## Compliance

### Audit Retention

For audit and compliance purposes:
- **Manifest metadata** retained for 1 year
- **Deployment records** retained for 1 year
- **Decision events** (Kafka) retained per separate policy

### Cannot Delete

- Current production version
- Previous production version (within 30-day window)
- Any version under active investigation

---

## Cost Optimization

### Estimated Storage Costs

| Storage Type | Estimated Size | Monthly Cost (approx.) |
|--------------|----------------|------------------------|
| Active (last 10 versions) | ~50 MB per ruleset | $0.001 per ruleset |
| Archive (90 days to 1 year) | ~100 MB per ruleset | $0.001 per ruleset |
| Total (10 rulesets) | ~1.5 GB | < $0.02/month |

---

## Cleanup Process

### Automated Cleanup

Run weekly:

```bash
# Archive versions older than 30 days (but keep last 10)
# Delete versions older than 1 year
# This is typically handled by S3 lifecycle policies
```

### S3 Lifecycle Policy Example

```json
{
  "Rules": [
    {
      "Id": "archive-old-versions",
      "Status": "Enabled",
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "GLACIER"
        }
      ],
      "Expiration": {
        "Days": 365
      }
    }
  ]
}
```

---

## Exceptions

Exceptions to retention policy require:

1. **Incident investigation** - Keep until investigation closed
2. **Regulatory hold** - Keep until hold released
3. **Security investigation** - Keep indefinitely until cleared

---

## Implementation

**Status:** [ ] Pending

To implement:
- [ ] Configure S3 lifecycle rules
- [ ] Add cleanup job to rule-management service
- [ ] Document rollback procedures

---

**End of Document**
