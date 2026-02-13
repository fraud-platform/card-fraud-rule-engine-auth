# FieldRegistry Contract

**Version:** 1.0
**Last Updated:** 2026-01-24
**Owners:** Fraud Engineering Team

## Overview

The FieldRegistry is the single source of truth for field identifiers used in rule evaluation. This document defines the contract between the rule-management service (which creates rules) and the rule-engine (which evaluates them).

## Purpose

Maintaining a consistent field registry across both services ensures:

1. **Correctness**: Rules reference valid fields that the engine can evaluate
2. **Performance**: Integer field IDs enable O(1) lookups vs string comparisons
3. **Compatibility**: Schema changes are coordinated to prevent runtime failures

## Field Registry Structure

### Standard Fields

| Field ID | Field Name | Type | Description |
|----------|------------|------|-------------|
| 0 | transaction_id | String | Unique transaction identifier |
| 1 | card_hash | String | Hashed card number (PCI compliant) |
| 2 | amount | BigDecimal | Transaction amount |
| 3 | currency | String | ISO 4217 currency code |
| 4 | merchant_id | String | Merchant identifier |
| 5 | merchant_name | String | Merchant display name |
| 6 | merchant_category | String | Merchant category description |
| 7 | merchant_category_code | String | MCC (4-digit code) |
| 8 | card_present | Boolean | Physical card present |
| 9 | transaction_type | String | PURCHASE, REFUND, etc. |
| 10 | entry_mode | String | CHIP, SWIPE, MANUAL, etc. |
| 11 | country_code | String | ISO 3166-1 alpha-2 |
| 12 | ip_address | String | Client IP address |
| 13 | device_id | String | Device fingerprint |
| 14 | email | String | Customer email |
| 15 | phone | String | Customer phone |
| 16 | timestamp | Instant | Transaction timestamp |
| 17 | billing_city | String | Billing address city |
| 18 | billing_country | String | Billing address country |
| 19 | billing_postal_code | String | Billing postal code |
| 20 | shipping_city | String | Shipping address city |
| 21 | shipping_country | String | Shipping address country |
| 22 | shipping_postal_code | String | Shipping postal code |
| 23 | card_network | String | VISA, MASTERCARD, AMEX, etc. |
| 24 | card_bin | String | Bank Identification Number (6-8 digits) |
| 25 | card_logo | String | Card brand/logo |

### Field Aliases

For convenience, certain aliases are supported:

| Alias | Maps To |
|-------|---------|
| txn_id | transaction_id |
| card | card_hash |
| merch_id | merchant_id |
| merch_category | merchant_category |
| mcc | merchant_category_code |
| ip | ip_address |
| device | device_id |
| network | card_network |
| bin | card_bin |
| logo | card_logo |

## Contract Rules

### Adding New Fields

1. **Coordination Required**: New fields must be added to both services simultaneously
2. **Sequential IDs**: New fields receive the next available ID (no gaps)
3. **Backward Compatible**: Existing field IDs never change
4. **Documentation**: Update this document and release notes

#### Process

1. Create PR in rule-engine adding field to `FieldRegistry.java` and `TransactionContext.java`
2. Create PR in rule-management adding field to schema validation
3. Review and merge both PRs together
4. Deploy rule-engine first, then rule-management

### Removing Fields

**Fields are never removed.** Instead:

1. Mark as deprecated in documentation
2. Add validation warning in rule-management
3. Continue supporting in rule-engine indefinitely

### Renaming Fields

**Field names never change.** To "rename":

1. Add new field with new name
2. Add alias from old name to new name
3. Deprecate old name in documentation
4. Update rule-management to warn on old name usage

## Validation

### Rule-Management Service

When a rule is created/updated:

```python
def validate_condition_field(field_name: str) -> bool:
    """Validates that a field name is known to the engine."""
    known_fields = {
        "transaction_id", "card_hash", "amount", "currency",
        "merchant_id", "merchant_name", "merchant_category",
        "merchant_category_code", "card_present", "transaction_type",
        "entry_mode", "country_code", "ip_address", "device_id",
        "email", "phone", "timestamp", "billing_city", "billing_country",
        "billing_postal_code", "shipping_city", "shipping_country",
        "shipping_postal_code", "card_network", "card_bin", "card_logo",
        # Aliases
        "txn_id", "card", "merch_id", "merch_category", "mcc",
        "ip", "device", "network", "bin", "logo"
    }
    return field_name in known_fields
```

### Rule-Engine Service

The engine uses `FieldRegistry.fromName()` which returns `UNKNOWN (-1)` for unrecognized fields. Unknown fields are handled gracefully (null value in evaluation).

## Custom Fields

For fields not in the standard registry:

1. Pass in `custom_fields` map in transaction context
2. Reference as `custom_fields.field_name` in rules
3. Performance note: Custom fields use HashMap lookup (slower than standard fields)

```json
{
  "transaction_id": "txn-123",
  "amount": 100.00,
  "custom_fields": {
    "loyalty_tier": "GOLD",
    "account_age_days": 365
  }
}
```

## Versioning

The FieldRegistry does not have explicit versioning. Instead:

1. **FIELD_COUNT** constant indicates the current number of fields
2. Engine logs field count at startup
3. Mismatches between services trigger warnings

### Compatibility Check

Rule-management should verify compatibility on startup:

```python
# Check that published rulesets use supported fields
def check_ruleset_compatibility(ruleset: Ruleset, engine_fields: set) -> list[str]:
    warnings = []
    for rule in ruleset.rules:
        for field in extract_fields(rule.condition):
            if field not in engine_fields:
                warnings.append(f"Rule {rule.id} uses unknown field: {field}")
    return warnings
```

## Testing

### Unit Tests

Both services must have tests verifying:

1. All standard fields are recognized
2. All aliases resolve correctly
3. Unknown fields return appropriate value
4. Field count matches expected

### Integration Tests

Test ruleset with all field types:

```yaml
rules:
  - id: field-coverage-test
    condition:
      and:
        - field: amount
          operator: gte
          value: 0
        - field: card_hash
          operator: exists
        - field: custom_fields.test_field
          operator: eq
          value: "test"
```

## Monitoring

Metrics to track field usage:

- `rule_field_usage{field="amount"}` - Counter of field evaluations
- `rule_unknown_field_total` - Counter of unknown field references
- `rule_custom_field_total` - Counter of custom field lookups

Alert on:

- Unknown field references (may indicate version mismatch)
- High custom field usage (may indicate need for new standard field)

## Related Documents

- [FieldRegistry.java](../../src/main/java/com/fraud/engine/domain/FieldRegistry.java)
- [TransactionContext.java](../../src/main/java/com/fraud/engine/domain/TransactionContext.java)
- [Rule Schema Specification](./rule-schema.md)
