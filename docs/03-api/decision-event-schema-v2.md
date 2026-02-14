# Decision Event Schema v2.0

This document describes the enhanced decision event schema emitted by the rule engine to Kafka topic `fraud.card.decisions.v1`.

**Version:** 2.0
**Last Updated:** 2026-01-27
**Compatible With:** transaction-management DecisionEventCreate schema

---

## Overview

The enhanced decision event provides complete visibility into:
1. **Full transaction context** - All transaction fields for downstream processing
2. **Velocity snapshot** - All velocity dimensions checked (not just exceeded ones)
3. **Engine metadata** - Processing mode, errors, timing, version
4. **Condition details** - Which conditions matched and their actual values

---

## Event Envelope

```json
{
  "transaction_id": "string (required)",
  "occurred_at": "ISO8601 timestamp (required)",
  "produced_at": "ISO8601 timestamp (required)",
  "decision": "APPROVE | DECLINE (required)",
  "decision_reason": "RULE_MATCH | VELOCITY_MATCH | DEFAULT_ALLOW | SYSTEM_DECLINE (required)",
  "evaluation_type": "AUTH | MONITORING (required)",
  "ruleset_key": "CARD_AUTH | CARD_MONITORING (required)",
  "ruleset_version": "integer (required)",
  "ruleset_id": "UUID (optional)",
  "risk_level": "LOW | HIGH (required)",
  "velocity_results": { "...": "object (optional)" }
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `transaction_id` | string | Yes | Unique transaction identifier |
| `occurred_at` | string | Yes | When the transaction occurred (client timestamp) |
| `produced_at` | string | Yes | When the decision event was produced |
| `decision` | enum | Yes | Final decision (APPROVE, DECLINE) |
| `decision_reason` | enum | Yes | Primary reason for the decision |
| `evaluation_type` | enum | Yes | AUTH or MONITORING |
| `ruleset_key` | string | Yes | Ruleset key (CARD_AUTH/CARD_MONITORING) |
| `ruleset_version` | integer | Yes | Ruleset version |
| `ruleset_id` | string | No | Ruleset UUID (if available) |
| `risk_level` | enum | Yes | Computed risk level based on decision |
| `velocity_results` | object | No | Per-rule velocity calculation results |

---

## Transaction Details

```json
{
  "transaction": {
    "occurred_at": "ISO8601 timestamp (required)",
    "card_id": "string (tokenized, required)",
    "card_last4": "string (optional)",
    "card_network": "VISA | MC | AMEX | DISCOVER | JCB (optional)",
    "amount": "number (required)",
    "currency": "ISO4217 code (required)",
    "country": "ISO3166-1 alpha-2 (required)",
    "merchant_id": "string (required)",
    "mcc": "string (optional)",
    "ip": "string (optional)"
  }
}
```

### Field Descriptions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `occurred_at` | string | Yes | Transaction timestamp |
| `card_id` | string | Yes | Tokenized card identifier (card_hash) |
| `card_last4` | string | No | Last 4 digits of card number |
| `card_network` | enum | No | Card network (VISA, MC, AMEX, DISCOVER, JCB) |
| `amount` | number | Yes | Transaction amount |
| `currency` | string | Yes | ISO 4217 currency code (USD, EUR, GBP, etc.) |
| `country` | string | Yes | ISO 3166-1 alpha-2 country code |
| `merchant_id` | string | Yes | Merchant identifier |
| `mcc` | string | No | Merchant Category Code |
| `ip` | string | No | IP address of the transaction |

---

## Transaction Context (Full Payload)

```json
{
  "transactionContext": {
    "transaction_id": "string",
    "card_hash": "string",
    "amount": 5200,
    "currency": "USD",
    "merchant_id": "M12345",
    "merchant_name": "AMAZON",
    "merchant_category": "RETAIL",
    "merchant_category_code": "5411",
    "country_code": "US",
    "ip_address": "10.1.2.3",
    "device_id": "device_abc",
    "email": "user@example.com",
    "phone": "+1234567890",
    "card_network": "VISA",
    "card_bin": "411111",
    "card_logo": "VISA",
    "entry_mode": "ECOM",
    "card_present": false,
    "transaction_type": "PURCHASE",
    "timestamp": "2026-01-25T10:45:30Z",
    "custom_fields": {
      "loyalty_tier": "GOLD",
      "ip_risk_score": 15
    }
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `transaction_id` | string | Unique transaction identifier |
| `card_hash` | string | Tokenized card identifier |
| `amount` | number | Transaction amount in minor units |
| `currency` | string | ISO 4217 currency code |
| `merchant_id` | string | Merchant identifier |
| `merchant_name` | string | Merchant business name |
| `merchant_category` | string | Merchant category |
| `merchant_category_code` | string | MCC (4 digits) |
| `country_code` | string | ISO 3166-1 alpha-2 country code |
| `ip_address` | string | IP address (IPv4 or IPv6) |
| `device_id` | string | Device fingerprint/identifier |
| `email` | string | User email address |
| `phone` | string | User phone number |
| `card_network` | string | Card network (VISA, MC, AMEX, etc.) |
| `card_bin` | string | Bank Identification Number (first 6-8 digits) |
| `card_logo` | string | Card brand logo identifier |
| `entry_mode` | string | Entry mode (ECOM, CHIP, SWIPE, CONTACTLESS) |
| `card_present` | boolean | Whether physical card was present |
| `transaction_type` | string | Transaction type (PURCHASE, REFUND, etc.) |
| `timestamp` | string | ISO8601 transaction timestamp |
| `custom_fields` | object | Additional custom fields (flexible schema) |

---

## Velocity Snapshot

```json
{
  "velocitySnapshot": {
    "card_5min": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 4,
      "threshold": 3,
      "windowSeconds": 300,
      "exceeded": true,
      "ttlRemaining": 127
    },
    "card_1h": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 8,
      "threshold": 10,
      "windowSeconds": 3600,
      "exceeded": false,
      "ttlRemaining": 2403
    },
    "card_24h": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 15,
      "threshold": 50,
      "windowSeconds": 86400,
      "exceeded": false,
      "ttlRemaining": 72034
    },
    "ip_1h": {
      "dimension": "ip_address",
      "dimensionValue": "10.1.2.3",
      "count": 2,
      "threshold": 20,
      "windowSeconds": 3600,
      "exceeded": false,
      "ttlRemaining": 1800
    },
    "ip_24h": {
      "dimension": "ip_address",
      "dimensionValue": "10.1.2.3",
      "count": 5,
      "threshold": 100,
      "windowSeconds": 86400,
      "exceeded": false,
      "ttlRemaining": 65000
    },
    "device_1h": {
      "dimension": "device_id",
      "dimensionValue": "device_abc",
      "count": 1,
      "threshold": 5,
      "windowSeconds": 3600,
      "exceeded": false,
      "ttlRemaining": 3000
    },
    "device_24h": {
      "dimension": "device_id",
      "dimensionValue": "device_abc",
      "count": 3,
      "threshold": 20,
      "windowSeconds": 86400,
      "exceeded": false,
      "ttlRemaining": 70000
    }
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `dimension` | string | Dimension name (card_hash, ip_address, device_id) |
| `dimensionValue` | string | Actual value being tracked (tokenized) |
| `count` | integer | Current counter value |
| `threshold` | integer | Threshold configured for this dimension/window |
| `windowSeconds` | integer | Time window in seconds |
| `exceeded` | boolean | Whether threshold was exceeded |
| `ttlRemaining` | long | Seconds until counter window resets |

### Snapshot Keys

| Key | Dimension | Window | Purpose |
|-----|-----------|--------|---------|
| `card_5min` | card_hash | 300s | Rapid card velocity fraud |
| `card_1h` | card_hash | 3600s | Hourly card velocity |
| `card_24h` | card_hash | 86400s | Daily card velocity |
| `ip_1h` | ip_address | 3600s | IP-based fraud detection |
| `ip_24h` | ip_address | 86400s | Daily IP patterns |
| `device_1h` | device_id | 3600s | Device-based fraud |
| `device_24h` | device_id | 86400s | Daily device patterns |

---

## Matched Rules

```json
{
  "matchedRules": [
    {
      "rule_id": "amazon-high-velocity",
      "rule_version": 3,
      "rule_name": "Amazon High Velocity - Decline",
      "priority": 100,
      "rule_action": "DECLINE",
      "matched_at": "2026-01-25T10:45:30.123Z",
      "match_reason_text": "Rule: Amazon High Velocity - Decline; Conditions: merchant_name CONTAINS 'AMAZON', amount > 100, velocity(card_hash, 300s) >= 3",
      "conditions_met": [
        "merchant_name CONTAINS 'AMAZON'",
        "amount > 100",
        "velocity(card_hash, 300s) >= 3"
      ],
      "condition_values": {
        "merchant_name": "AMAZON",
        "amount": 5200
      }
    }
  ]
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Stable rule identifier |
| `rule_version` | integer | Rule version number |
| `rule_name` | string | Human-readable rule name |
| `priority` | integer | Rule priority (1-1000) |
| `rule_action` | enum | Action configured (APPROVE, DECLINE, REVIEW) |
| `matched_at` | string | ISO8601 timestamp of match |
| `match_reason_text` | string | Human-readable explanation |
| `conditions_met` | array | List of matched conditions in human-readable form |
| `condition_values` | object | Map of field names to actual values |

---

## Engine Metadata

```json
{
  "engineMetadata": {
    "engineMode": "NORMAL",
    "errorCode": null,
    "errorMessage": null,
    "processingTimeMs": 4.3,
    "ruleEngineVersion": "1.0.0"
  }
}
```

### Field Descriptions

| Field | Type | Description |
|-------|------|-------------|
| `engineMode` | enum | Engine mode (NORMAL, DEGRADED, FAIL_OPEN) |
| `errorCode` | string | Error code if not NORMAL |
| `errorMessage` | string | Human-readable error message |
| `processingTimeMs` | double | Total processing time in milliseconds |
| `ruleEngineVersion` | string | Engine version for traceability |

### Engine Mode Values

| Mode | Description | Decision Behavior |
|------|-------------|-------------------|
| `NORMAL` | All systems operational | Full rule evaluation |
| `DEGRADED` | Redis velocity unavailable | Skip velocity rules, evaluate others |
| `FAIL_OPEN` | Critical system failure | Default to APPROVE |

### Error Codes

| Code | Description | Mode |
|------|-------------|------|
| `REDIS_UNAVAILABLE` | Redis connection failed | DEGRADED |
| `RULESET_NOT_LOADED` | Ruleset failed to load | FAIL_OPEN |
| `ENGINE_EXCEPTION` | Unexpected engine error | FAIL_OPEN |
| `VALIDATION_ERROR` | Request validation failed | FAIL_OPEN |
| `TIMEOUT` | Processing timeout | FAIL_OPEN |

---

## Complete Example

```json
{
  "transaction_id": "txn_abc123",
  "occurred_at": "2026-01-25T10:45:30Z",
  "produced_at": "2026-01-25T10:45:30.043Z",
  "decision": "DECLINE",
  "decision_reason": "RULE_MATCH",
  "risk_level": "HIGH",

  "transaction": {
    "occurred_at": "2026-01-25T10:45:30Z",
    "card_id": "hash_visa_4111",
    "card_last4": "1111",
    "card_network": "VISA",
    "amount": 5200,
    "currency": "USD",
    "country": "US",
    "merchant_id": "M12345",
    "mcc": "5411",
    "ip": "10.1.2.3"
  },

  "transactionContext": {
    "transaction_id": "txn_abc123",
    "card_hash": "hash_visa_4111",
    "amount": 5200,
    "currency": "USD",
    "merchant_id": "M12345",
    "merchant_name": "AMAZON",
    "merchant_category": "RETAIL",
    "merchant_category_code": "5411",
    "country_code": "US",
    "ip_address": "10.1.2.3",
    "device_id": "device_abc",
    "card_network": "VISA",
    "card_bin": "411111",
    "entry_mode": "ECOM",
    "card_present": false,
    "transaction_type": "PURCHASE"
  },

  "velocitySnapshot": {
    "card_5min": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 4,
      "threshold": 3,
      "windowSeconds": 300,
      "exceeded": true,
      "ttlRemaining": 127
    },
    "card_1h": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 8,
      "threshold": 10,
      "windowSeconds": 3600,
      "exceeded": false
    },
    "card_24h": {
      "dimension": "card_hash",
      "dimensionValue": "hash_visa_4111",
      "count": 15,
      "threshold": 50,
      "windowSeconds": 86400,
      "exceeded": false
    },
    "ip_1h": {
      "dimension": "ip_address",
      "dimensionValue": "10.1.2.3",
      "count": 2,
      "threshold": 20,
      "windowSeconds": 3600,
      "exceeded": false
    },
    "ip_24h": {
      "dimension": "ip_address",
      "dimensionValue": "10.1.2.3",
      "count": 5,
      "threshold": 100,
      "windowSeconds": 86400,
      "exceeded": false
    },
    "device_1h": {
      "dimension": "device_id",
      "dimensionValue": "device_abc",
      "count": 1,
      "threshold": 5,
      "windowSeconds": 3600,
      "exceeded": false
    },
    "device_24h": {
      "dimension": "device_id",
      "dimensionValue": "device_abc",
      "count": 3,
      "threshold": 20,
      "windowSeconds": 86400,
      "exceeded": false
    }
  },

  "matchedRules": [
    {
      "rule_id": "amazon-high-velocity",
      "rule_version": 3,
      "rule_name": "Amazon High Velocity - Decline",
      "priority": 100,
      "rule_action": "DECLINE",
      "matched_at": "2026-01-25T10:45:30.123Z",
      "match_reason_text": "Rule: Amazon High Velocity - Decline; Conditions: merchant_name CONTAINS 'AMAZON', amount > 100, velocity(card_hash, 300s) >= 3",
      "conditions_met": [
        "merchant_name CONTAINS 'AMAZON'",
        "amount > 100",
        "velocity(card_hash, 300s) >= 3"
      ],
      "condition_values": {
        "merchant_name": "AMAZON",
        "amount": 5200
      }
    }
  ],

  "engineMetadata": {
    "engineMode": "NORMAL",
    "errorCode": null,
    "errorMessage": null,
    "processingTimeMs": 4.3,
    "ruleEngineVersion": "1.0.0"
  }
}
```

---

## Consumer Expectations

This event is consumed by **transaction-management** for:
- Storing decision records for audit/compliance
- Real-time fraud monitoring dashboards
- Chargeback/dispute support
- Analytics and reporting

### Consumer Requirements

| Requirement | Description |
|--------------|-------------|
| **Idempotency** | `transaction_id` is unique per evaluation - use as idempotency key |
| **Ordering** | Events are ordered by `produced_at` timestamp within a partition |
| **Topic** | `fraud.card.decisions.v1` |
| **Partitions** | Partitioned by `card_id` (card_hash) for data locality |
| **Retention** | 30 days (configurable per environment) |
| **Schema Evolution** | Backward compatible - new fields are additive only |

### Processing Guidelines

1. **Always store** `transaction_id` as the primary key
2. **Use `engine_mode`** to filter degraded/fail-open decisions for monitoring
3. **Parse `velocity_snapshot`** for real-time velocity analytics
4. **Handle both `decision_reason` values**: RULE_MATCH, VELOCITY_MATCH, DEFAULT_ALLOW, SYSTEM_DECLINE

---

## Backward Compatibility

This schema is **backward compatible** with v1.0:
- All v1.0 fields remain unchanged
- New fields are additive only
- Optional fields maintain nullability
- Breaking changes would require version bump to v3.0

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2026-01-25 | Enhanced schema with transactionContext, velocitySnapshot, engineMetadata, conditionsMet |
| 1.0 | 2026-01-17 | Initial specification |
