# Runbook: Artifact Checksum Mismatch

**Severity:** P2 - Medium
**Service:** card-fraud-rule-engine
**Component:** RulesetLoader
**Last Updated:** 2026-01-24

---

## Symptoms

- **Alerts:**
  - `RulesetLoadFailure` alert with error `ARTIFACT_CHECKSUM_MISMATCH`

- **Metrics:**
  - `ruleset_reload_total{result="failure"}` increasing
  - `ruleset_checksum_mismatch_total` > 0

- **Logs:**
  - `ERROR [RulesetLoader] Checksum mismatch for ruleset`
  - `Expected: <sha256>, Actual: <sha256>`

- **User-Visible Impact:**
  - New ruleset version not loaded
  - Engine continues serving previous version
  - May cause rule drift if intended changes not applied

---

## Impact

| Severity | Description |
|----------|-------------|
| **Operational** | New rules not applied; serving stale ruleset |
| **Financial** | New fraud patterns may not be detected |
| **Data** | Potential inconsistency between expected and actual rules |

**Note:** The engine will continue to serve the last successfully loaded ruleset, so this is not a service outage.

---

## Diagnosis

### 1. Identify Affected Ruleset

```bash
# Check which ruleset failed to load
curl -s http://localhost:8081/v1/manage/rulesets/status | jq

# Check recent reload attempts
grep "Checksum mismatch" /var/log/fraud-engine/app.log | tail -10
```

### 2. Verify Manifest Checksum

```bash
# Download manifest
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json . \
  --endpoint-url $S3_ENDPOINT_URL

# Check expected checksum
cat manifest.json | jq '.checksum'
```

### 3. Verify Artifact Checksum

```bash
# Download artifact
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml . \
  --endpoint-url $S3_ENDPOINT_URL

# Calculate actual checksum
sha256sum ruleset.yaml
```

### 4. Compare Results

If checksums don't match:
- Artifact may have been corrupted during upload
- Manifest may have wrong checksum
- Object storage may have data integrity issues

---

## Resolution

### Option A: Re-publish Artifact

If the artifact is correct but manifest has wrong checksum:

```bash
# In rule-management project
uv run publish-ruleset --ruleset CARD_AUTH --version v3 --force
```

### Option B: Re-upload Artifact

If artifact was corrupted:

```bash
# Re-upload the correct artifact
aws s3 cp ruleset.yaml s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Update manifest with correct checksum
# Then trigger reload
```

### Option C: Rollback to Previous Version

If unable to fix quickly:

```bash
# Update manifest to point to previous version
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey": "CARD_AUTH", "version": "v2"}'
```

### Post-Recovery Verification

```bash
# Verify reload succeeded
curl -s http://localhost:8081/v1/manage/rulesets/status | jq

# Verify correct version is serving
curl -s http://localhost:8081/v1/manage/rulesets/status | jq '.[].version'
```

---

## Prevention

1. **Pipeline Integrity:**
   - Compute checksum after upload, not before
   - Verify checksum after S3 upload completes

2. **Object Storage:**
   - Enable S3 object versioning
   - Use S3 checksum verification on upload

3. **Monitoring:**
   - Alert on any checksum mismatch
   - Track successful vs failed reloads

4. **Testing:**
   - Test artifact publishing in staging first
   - Validate artifacts before promoting to production

---

## Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | On-call SRE | Initial investigation |
| L2 | Platform Team | S3/MinIO issues |
| L3 | Fraud Engineering | Pipeline or content issues |

**Escalate to L2 if:**
- S3/MinIO connectivity or integrity issues
- Multiple artifacts affected

**Escalate to L3 if:**
- Publishing pipeline issues
- Need to investigate ruleset content

---

## How to Reproduce

### Test Scenario 1: Corrupted Upload

```bash
# Download valid artifact
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml ./ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Corrupt it
echo "CORRUPTED DATA" >> ruleset.yaml

# Re-upload corrupted version
aws s3 cp ruleset.yaml s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Trigger reload
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH","version":"v3"}'

# Observe checksum mismatch alert
```

### Test Scenario 2: Manifest/Artifact Desync

```bash
# Update artifact without updating manifest
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml ./ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Modify artifact content (valid YAML)
sed -i 's/amount: 100/amount: 200/' ruleset.yaml

# Re-upload but DON'T update manifest checksum
aws s3 cp ruleset.yaml s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Trigger reload - will fail with checksum mismatch
```

---

## How to Verify Fix

### 1. Verify Checksum Match

```bash
# Get manifest checksum
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json - \
  --endpoint-url $S3_ENDPOINT_URL | jq -r '.checksum'

# Calculate artifact checksum
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml - \
  --endpoint-url $S3_ENDPOINT_URL | sha256sum

# Compare - should match
```

### 2. Verify Reload Success

```bash
# Check ruleset status
curl -s http://localhost:8081/v1/manage/rulesets/status | jq

# Verify correct version loaded
curl -s http://localhost:8081/v1/manage/rulesets/status | jq '.[] | select(.rulesetKey=="CARD_AUTH") | .version'

# Check no recent checksum errors
grep "Checksum mismatch" /var/log/fraud-engine/app.log
# Expected: No entries after fix
```

### 3. Verify Rules Applied

```bash
# Test with transaction that should trigger specific rule
curl -X POST http://localhost:8081/v1/evaluate/auth \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"verify-rules-001","card_hash":"test-card","amount":999.00,"currency":"USD","merchant_category_code":"7995"}'

# Response should include matched_rules from new version
```

---

## Alerting Configuration

### Prometheus Rules

```yaml
groups:
  - name: checksum-alerts
    rules:
      - alert: ChecksumMismatch
        expr: ruleset_checksum_mismatch_total > 0
        for: 0s
        labels:
          severity: warning
        annotations:
          summary: "Ruleset checksum mismatch"
          description: "Checksum mismatch detected for {{ $labels.ruleset_key }}"

      - alert: ReloadFailureHigh
        expr: increase(ruleset_reload_total{result="failure"}[5m]) > 5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High ruleset reload failure rate"
          description: "{{ $value }} reload failures in last 5 minutes"
```

### Datadog Monitors

```json
{
  "name": "Checksum Mismatch Alert",
  "type": "metric alert",
  "query": "avg(last_5m):max:ruleset_checksum_mismatch_total > 0",
  "message": "Checksum mismatch detected. Re-publish artifact or update manifest.",
  "tags": ["service:card-fraud-rule-engine", "component:ruleset-loader"],
  "priority": 3
}
```

---

## Related Documentation

- [Artifact Retention Policy](./artifact-retention-policy.md)
- [Ruleset Reload Loop Runbook](./ruleset-reload-loop.md)
