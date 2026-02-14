# Rule Engine Design Update - Rule Management Service Requirements

**Date:** 2026-01-17
**Status:** For Implementation Review

## Executive Summary

The rule engine design has been updated to support:
1. Multi-country deployment (APAC, INDIA, EMEA, LATAM)
2. Scope-based rule bucketing (network, bin, mcc, logo)
3. Allow/Block lists as separate artifacts
4. Four artifacts per country

**Rule Management Service Impact:** Moderate - requires schema changes and compiler updates.

---

## Key Design Decisions (Locked)

### Scope Dimensions (4 Fixed)
| Dimension | Description | Examples |
|-----------|-------------|----------|
| `network` | Card network | VISA, MASTERCARD, AMEX |
| `bin` | Issuer BIN (6-digit) | 411111, 542523 |
| `mcc` | Merchant category code | 5411, 5812 |
| `logo` | Card product tier | CLASSIC, GOLD, PLATINUM |

### Scope Expression Format
```json
"scope": {
  "network": ["VISA", "MASTERCARD"],
  "bin": ["411111", "542523"]
}
```
- Multiple values per dimension = OR semantics
- Multiple dimensions = AND semantics
- No wildcards in scope values (enumerated only)

### Four Artifacts Per Country
| Artifact | Key | Purpose |
|----------|-----|---------|
| `allowlist` | ALLOWLIST | O(1) approve lookups |
| `blocklist` | BLOCKLIST | O(1) decline lookups |
| `CARD_AUTH` | CARD_AUTH | Decisioning rules |
| `CARD_MONITORING` | CARD_MONITORING | Analytics rules |

### S3 Layout
```
rulesets/{env}/{region}/{country}/{artifact_type}/v{version}/ruleset.json
```

Example:
- `rulesets/prod/APAC/SG/allowlist/v1/ruleset.json`
- `rulesets/prod/APAC/SG/CARD_AUTH/v42/ruleset.json`

---

## Required Changes in Rule Management

### 1. Schema Changes (app/db/models.py)

#### RuleVersion Additions
```python
class RuleVersion(Base):
    # ... existing fields ...

    # NEW: Scope metadata
    scope: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        default=None,
        comment="Scope dimensions: {network?, bin?, mcc?, logo?}"
    )

    # NEW: Allow/Block list action (null for regular rules)
    list_action: Mapped[str | None] = mapped_column(
        String,
        nullable=True,
        comment="APPROVE | DECLINE - for ALLOWLIST/BLOCKLIST only"
    )
```

#### RuleType Enum Update
Add:
- `ALLOWLIST`
- `BLOCKLIST`

#### Validation Constraints
```python
__table_args__ = (
    # ... existing ...

    # Allow/Block list must have null scope
    CheckConstraint(
        """
        (rule_type IN ('AUTH', 'MONITORING') AND scope IS NOT NULL)
        OR
        (rule_type IN ('ALLOWLIST', 'BLOCKLIST') AND scope IS NULL)
        """,
        name="chk_rule_version_list_scope"
    ),

    # Allow/Block list must have list_action
    CheckConstraint(
        """
        (rule_type IN ('AUTH', 'MONITORING') AND list_action IS NULL)
        OR
        (rule_type IN ('ALLOWLIST', 'BLOCKLIST') AND list_action IN ('APPROVE', 'DECLINE'))
        """,
        name="chk_rule_version_list_action"
    ),
)
```

---

### 2. Compiler Changes (app/compiler/compiler.py)

#### New Method: Scope Bucket Assignment
```python
def _assign_scope_buckets(
    self,
    rules: list[RuleVersion]
) -> dict[str, list[RuleVersion]]:
    """Assign rules to scope buckets for efficient runtime lookup."""
    buckets = defaultdict(list)

    for rule in rules:
        if rule.scope is None or rule.scope == {}:
            bucket_key = "country-only"
        else:
            key_parts = []
            for dim in ["network", "bin", "mcc", "logo"]:
                if dim in rule.scope:
                    values = sorted(rule.scope[dim])
                    key_parts.append(f"{dim}:{','.join(values)}")
            bucket_key = "|".join(key_parts)
        buckets[bucket_key].append(rule)

    # Sort each bucket by priority
    for bucket in buckets.values():
        bucket.sort(key=lambda r: r.priority)

    return dict(buckets)
```

#### New Method: List Compilation
```python
def _compile_list(
    self,
    list_entries: list[RuleVersion]
) -> CompiledList:
    """Compile allow/block list to O(1) lookup structure."""
    index = {}
    for entry in list_entries:
        index[entry.card_id] = {
            "action": entry.list_action,
            "conditions": entry.condition_tree
        }
    return CompiledList(entries=index)
```

#### Updated: compile_ruleset Method
```python
def compile_ruleset(
    self,
    ruleset_id: UUID,
    rule_versions: list[RuleVersion],
    region: str,
    country: str
) -> CompiledCountryArtifacts:
    """Compile 4 artifacts per country."""

    # Separate by rule_type
    allowlist = [v for v in rule_versions if v.rule_type == RuleType.ALLOWLIST]
    blocklist = [v for v in rule_versions if v.rule_type == RuleType.BLOCKLIST]
    auth_rules = [v for v in rule_versions if v.rule_type == RuleType.AUTH]
    monitoring_rules = [v for v in rule_versions if v.rule_type == RuleType.MONITORING]

    # Scope bucket assignment
    scope_buckets = self._assign_scope_buckets(auth_rules + monitoring_rules)

    return CompiledCountryArtifacts(
        region=region,
        country=country,
        allowlist=self._compile_list(allowlist),
        blocklist=self._compile_list(blocklist),
        card_auth=self._compile_scoped_ruleset(auth_rules, scope_buckets, "FIRST_MATCH"),
        card_monitoring=self._compile_scoped_ruleset(monitoring_rules, scope_buckets, "ALL_MATCHING")
    )
```

---

### 3. Publisher Changes (app/services/ruleset_publisher.py)

#### Updated: publish_country_artifacts
```python
async def publish_country_artifacts(
    self,
    region: str,
    country: str,
    compiled_artifacts: CompiledCountryArtifacts,
    environment: str
) -> dict[str, RulesetManifest]:
    """Publish 4 artifacts per country to S3."""

    base_path = f"rulesets/{environment}/{region}/{country}"
    results = {}

    for artifact_type, artifact in [
        ("allowlist", compiled_artifacts.allowlist),
        ("blocklist", compiled_artifacts.blocklist),
        ("CARD_AUTH", compiled_artifacts.card_auth),
        ("CARD_MONITORING", compiled_artifacts.card_monitoring)
    ]:
        artifact_path = f"{base_path}/{artifact_type}/v{artifact.version}/ruleset.json"
        artifact_uri = await self._upload_artifact(artifact_path, artifact.json_bytes)
        checksum = self._compute_checksum(artifact.json_bytes)

        manifest = RulesetManifest(
            environment=environment,
            ruleset_key=artifact_type,
            region=region,
            country=country,
            ruleset_version=artifact.version,
            artifact_uri=artifact_uri,
            checksum=checksum
        )

        await self._write_manifest(manifest)
        results[artifact_type] = manifest

    return results
```

---

### 4. API Validation Updates

#### Scope Validation at Rule Creation
- Validate scope dimensions are in allowed set (network, bin, mcc, logo)
- Validate scope values are non-empty strings (no wildcards)
- Warn on unknown values but allow
- Reject invalid scope format

#### Allow/Block List Validation
- `rule_type` must be `ALLOWLIST` or `BLOCKLIST`
- `scope` must be null
- `card_id` must be present
- `list_action` must be `APPROVE` or `DECLINE`
- `priority` must be null

---

## Validation Rules Summary

| Scenario | Rule | Validation |
|----------|------|------------|
| Regular AUTH rule | scope can be null or {} | Warn if null, country-only |
| Regular AUTH rule | scope can have network/bin/mcc/logo | Validate values |
| Allow/Block list rule | scope must be null | Reject if present |
| Allow/Block list rule | list_action must be APPROVE/DECLINE | Reject if missing |
| Any rule | scope values must be exact strings | Reject wildcards |
| Any rule | scope values must be non-empty | Reject empty strings |

---

## Testing Requirements

### Unit Tests Needed
1. Scope bucket assignment with various scope combinations
2. Scope validation (valid and invalid cases)
3. Allow/Block list creation and validation
4. Priority ordering within scope buckets
5. Compiler output for all 4 artifact types

### Integration Tests Needed
1. End-to-end compile → publish flow
2. S3 artifact structure verification
3. Manifest creation for multi-artifact publish

---

## Dependencies

| Depends On | Description |
|------------|-------------|
| Rule Engine Runtime | Must implement multi-stage evaluation |
| Transaction Management | Must accept `issuing_country` in events |
| S3/MinIO | Must support region/country path structure |

---

## Files to Modify

| File | Change Type |
|------|-------------|
| `app/db/models.py` | Add scope, list_action fields + constraints |
| `app/domain/enums.py` | Add ALLOWLIST, BLOCKLIST |
| `app/compiler/compiler.py` | Add scope bucketing, list compilation |
| `app/services/ruleset_publisher.py` | Update for multi-artifact publish |
| `tests/test_unit_*.py` | Add scope validation tests |

---

## Timeline Estimate

| Phase | Duration | Description |
|-------|----------|-------------|
| Schema changes | 2-4 hours | Add fields, constraints |
| Compiler updates | 8-12 hours | Scope bucketing, list compilation |
| Publisher updates | 4-6 hours | Multi-artifact publish |
| Testing | 8-12 hours | Unit + integration tests |
| **Total** | **22-34 hours** | |

---

## Questions for Clarification

1. Should scope validation warn or reject unknown network/BIN values?
2. Should the compiler emit separate version numbers for each artifact type?
3. Should PN lists support `card_id` patterns (e.g., BIN-only lookups)?

---

## Related Documentation

- [Compiled Ruleset Format Plan](../02-development/README.md)
- [Object Storage Artifacts Plan](../02-development/README.md)
- [Runtime API Plan](../02-development/README.md)
- [Scope & Components](../02-development/README.md)

