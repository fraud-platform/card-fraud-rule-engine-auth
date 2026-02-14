# Runbook: Ruleset Reload Loop

**Severity:** P2 - Medium
**Service:** card-fraud-rule-engine
**Component:** RulesetLoader / RulesetRegistry
**Last Updated:** 2026-01-24

---

## Symptoms

- **Alerts:**
  - `RulesetReloadLoopDetected` alert firing
  - `HighReloadFailureRate` alert firing

- **Metrics:**
  - `ruleset_reload_total{result="failure"}` increasing rapidly
  - `ruleset_reload_attempts_total` unusually high
  - Gap between reload attempts much shorter than configured interval

- **Logs:**
  - Repeated `ERROR [RulesetLoader] Failed to load ruleset` messages
  - Same error repeating every few seconds
  - `WARN [RulesetRegistry] Reload failed, keeping previous version`

- **User-Visible Impact:**
  - Increased CPU/memory usage from repeated load attempts
  - Potential for log spam filling disk
  - New ruleset versions not being applied

---

## Impact

| Severity | Description |
|----------|-------------|
| **Operational** | Resource waste from repeated failed attempts |
| **Financial** | New rules not applied; serving stale version |
| **Stability** | High reload rate may impact request processing |

**Note:** The engine will continue serving the last successfully loaded ruleset. This issue affects the ability to update rules, not current operations.

---

## Diagnosis

### 1. Identify Failure Mode

```bash
# Check recent reload errors
grep "Failed to load ruleset" /var/log/fraud-engine/app.log | tail -20

# Common failure modes:
# - Download failure (network, S3)
# - Checksum mismatch
# - Schema version incompatibility
# - Parse error (invalid YAML)
# - Size limit exceeded
```

### 2. Check for Manifest Flapping

```bash
# Watch manifest version changes
watch -n 5 'aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json - \
  --endpoint-url $S3_ENDPOINT_URL | jq .version'

# Check for rapid version changes
aws s3api list-object-versions --bucket fraud-gov-artifacts \
  --prefix rulesets/CARD_AUTH/manifest.json \
  --endpoint-url $S3_ENDPOINT_URL | jq '.Versions | length'
```

### 3. Check Artifact Issues

```bash
# Check artifact size
aws s3 ls s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ --endpoint-url $S3_ENDPOINT_URL

# Download and validate artifact
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v3/ruleset.yaml . \
  --endpoint-url $S3_ENDPOINT_URL

# Check YAML validity
python -c "import yaml; yaml.safe_load(open('ruleset.yaml'))"
```

### 4. Check Schema Compatibility

```bash
# Check schema version in artifact
head -20 ruleset.yaml | grep schema_version

# Compare with supported schema versions
# Engine supports: schema_version: "1.0", "1.1"
```

---

## Resolution

### Stop the Loop Temporarily

```bash
# Option 1: Disable auto-reload (if supported)
kubectl set env deployment/fraud-engine RULESET_AUTO_RELOAD=false -n fraud-engine

# Option 2: Scale down temporarily
kubectl scale deployment fraud-engine --replicas=1 -n fraud-engine
```

### Fix Root Cause

#### Invalid Artifact Content

```bash
# Validate and fix YAML
python -c "import yaml; yaml.safe_load(open('ruleset.yaml'))"

# Re-publish corrected artifact
cd ../card-fraud-rule-management
uv run publish-ruleset --ruleset CARD_AUTH --version v3 --force
```

#### Schema Version Mismatch

```bash
# Update schema version in artifact to supported version
# Or upgrade engine to support new schema version
```

#### Size Limit Exceeded

```bash
# Check artifact size
ls -la ruleset.yaml

# If too large, optimize ruleset or increase limit
# Default limit: 1MB
```

### Rollback to Last-Known-Good

```bash
# Update manifest to point to working version
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey": "CARD_AUTH", "version": "v2"}'
```

### Re-enable Auto-Reload

```bash
# Re-enable if disabled
kubectl set env deployment/fraud-engine RULESET_AUTO_RELOAD=true -n fraud-engine

# Verify reload succeeds
curl -s http://localhost:8081/v1/manage/rulesets/status | jq
```

---

## Prevention

1. **Validation Pipeline:**
   - Validate YAML syntax before publishing
   - Check schema version compatibility
   - Enforce size limits in CI/CD

2. **Staged Rollouts:**
   - Test new rulesets in staging first
   - Use canary deployments for production

3. **Backoff Strategy:**
   - Engine should implement exponential backoff
   - Avoid tight reload loops on repeated failures

4. **Monitoring:**
   - Alert on reload failure rate
   - Track time since last successful reload

5. **Versioning:**
   - Maintain multiple artifact versions
   - Easy rollback capability

---

## Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | On-call SRE | Initial triage, rollback |
| L2 | Platform Team | Infrastructure issues |
| L3 | Fraud Engineering | Content or schema issues |

**Escalate to L2 if:**
- S3/MinIO infrastructure problems
- Network issues causing download failures

**Escalate to L3 if:**
- Ruleset content issues
- Schema version changes needed
- Publishing pipeline bugs

---

## How to Reproduce

### Test Scenario 1: Invalid YAML in Ruleset

```bash
# Create invalid YAML
cat > /tmp/bad-ruleset.yaml << 'EOF'
rules:
  - name: bad rule
    conditions:
      - field: amount
        operator: >
        value: [invalid yaml
    action: DECLINE
EOF

# Publish to MinIO
aws s3 cp /tmp/bad-ruleset.yaml s3://fraud-gov-artifacts/rulesets/CARD_AUTH/v99/ruleset.yaml \
  --endpoint-url $S3_ENDPOINT_URL

# Update manifest with new version
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json /tmp/manifest.json
cat /tmp/manifest.json | jq '.version = "v99" | .checksum = "'$(sha256sum /tmp/bad-ruleset.yaml | cut -d' ' -f1)'"' > /tmp/new-manifest.json
aws s3 cp /tmp/new-manifest.json s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json \
  --endpoint-url $S3_ENDPOINT_URL

# Watch reload loop
tail -f /var/log/fraud-engine/app.log | grep "Failed to load ruleset"
```

### Test Scenario 2: Schema Version Mismatch

```bash
# Create ruleset with unsupported schema version
cat > /tmp/wrong-schema.yaml << 'EOF'
schema_version: "99.0"
rules:
  - name: future rule
    conditions: []
    action: DECLINE
EOF

# Publish and observe reload failures
```

### Test Scenario 3: Manifest Version Flapping

```bash
# Rapidly change manifest version
for version in v1 v2 v3 v4 v3 v2; do
  aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json /tmp/manifest.json
  cat /tmp/manifest.json | jq ".version = \"$version\"" > /tmp/new-manifest.json
  aws s3 cp /tmp/new-manifest.json s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json \
    --endpoint-url $S3_ENDPOINT_URL
  sleep 0.5
done

# Observe rapid reload attempts
```

---

## How to Verify Fix

### 1. Verify No Reload Loop

```bash
# Check reload rate
curl -s http://localhost:8081/q/metrics | grep "ruleset_reload_attempts_total"
# Expected: Rate < 1 per minute (not rapid succession)

# Check for recent reload errors
grep "Failed to load ruleset" /var/log/fraud-engine/app.log | tail -10
# Expected: No rapid repeated failures

# Check circuit breaker status
curl -s http://localhost:8081/q/metrics | grep "circuit_breaker_state.*ruleset"
# Expected: state=closed
```

### 2. Verify Correct Version Loaded

```bash
# Check ruleset status
curl -s http://localhost:8081/v1/manage/rulesets/status | jq

# Verify expected version
curl -s http://localhost:8081/v1/manage/rulesets/status | jq '.[] | select(.rulesetKey=="CARD_AUTH") | .version'
# Expected: Shows the intended version

# Check reload result metrics
curl -s http://localhost:8081/q/metrics | grep "ruleset_reload_total"
# Expected: result="success" increasing, result="failure" not increasing
```

### 3. Verify Backoff Active

```bash
# Check time between reload attempts
grep "Reload failed" /var/log/fraud-engine/app.log | awk '{print $1, $2}' | head -10
# Expected: Increasing intervals (exponential backoff)

# If no backoff: entries every few seconds
# With backoff: entries at increasing intervals (10s, 20s, 40s, etc.)
```

### 4. Verify Rules Work

```bash
# Test evaluation with ruleset
curl -X POST http://localhost:8081/v1/evaluate/auth \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"verify-loop-fixed","card_hash":"test","amount":100.00,"currency":"USD"}'

# Response should be successful with decision
# matched_rules should contain expected rules
```

---

## Alerting Configuration

### Prometheus Rules

```yaml
groups:
  - name: reload-loop-alerts
    rules:
      - alert: RulesetReloadLoopDetected
        expr: |
          increase(ruleset_reload_attempts_total[1m]) > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Ruleset reload loop detected"
          description: "{{ $value }} reload attempts per minute - potential loop"

      - alert: HighReloadFailureRate
        expr: |
          sum(rate(ruleset_reload_total{result="failure"}[5m])) /
          sum(rate(ruleset_reload_total[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High ruleset reload failure rate"
          description: "{{ $value | humanizePercentage }} of reloads failing"

      - alert: ReloadBackoffActive
        expr: ruleset_reload_backoff_active == 1
        for: 5m
        labels:
          severity: info
        annotations:
          summary: "Reload backoff active"
          description: "Engine has activated reload backoff to prevent loop"

      - alert: StaleRulesetVersion
        expr: time() - ruleset_last_successful_reload_timestamp > 3600
        for: 5m
        labels:
          warning: warning
        annotations:
          summary: "Ruleset not updated in over 1 hour"
          description: "No successful reload for {{ $labels.ruleset_key }}"
```

### Datadog Monitors

```json
{
  "name": "Reload Loop Detection",
  "type": "metric alert",
  "query": "avg(last_2m):sum:ruleset_reload_attempts_total > 10",
  "message": "Potential ruleset reload loop detected. Check artifact validity.",
  "tags": ["service:card-fraud-rule-engine", "component:ruleset-loader"],
  "priority": 2
}
```

---

## Related Documentation

- [Checksum Mismatch Runbook](./checksum-mismatch.md)
- [Manifest Query Failure Runbook](./manifest-query-failure.md)
- [Artifact Retention Policy](./artifact-retention-policy.md)
