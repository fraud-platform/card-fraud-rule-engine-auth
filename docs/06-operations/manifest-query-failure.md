# Runbook: Manifest Query Failure

**Severity:** P2 - Medium
**Service:** card-fraud-rule-engine
**Component:** RulesetLoader
**Last Updated:** 2026-01-24

---

## Symptoms

- **Alerts:**
  - `ManifestFetchFailure` alert firing
  - `RulesetReloadFailure` alert firing

- **Metrics:**
  - `ruleset_reload_total{result="failure"}` increasing
  - `manifest_fetch_errors_total` > 0

- **Logs:**
  - `ERROR [RulesetLoader] Failed to fetch manifest.json`
  - `ERROR S3 connection refused`
  - `ERROR TLS handshake failed`
  - `ERROR AccessDenied`

- **User-Visible Impact:**
  - New ruleset versions not loaded
  - Engine continues serving last-known-good ruleset
  - May cause staleness if new rules are expected

---

## Impact

| Severity | Description |
|----------|-------------|
| **Operational** | Unable to receive ruleset updates |
| **Financial** | New fraud detection rules not applied |
| **Recovery** | Will recover automatically when S3 connectivity restored |

**Note:** This is non-critical if a valid ruleset is already loaded. The engine continues serving the last successfully loaded ruleset.

---

## Diagnosis

### 1. Verify S3/MinIO Connectivity

```bash
# Test basic connectivity
aws s3 ls s3://fraud-gov-artifacts/ --endpoint-url $S3_ENDPOINT_URL

# If using MinIO locally
docker exec card-fraud-rule-management-minio mc ls local/fraud-gov-artifacts/
```

### 2. Check Credentials

```bash
# Verify credentials are set
doppler secrets --project=card-fraud-rule-engine --config=local get S3_ACCESS_KEY_ID
doppler secrets --project=card-fraud-rule-engine --config=local get S3_SECRET_ACCESS_KEY

# Test credentials work
aws s3api head-bucket --bucket fraud-gov-artifacts --endpoint-url $S3_ENDPOINT_URL
```

### 3. Check TLS/Certificate Issues

```bash
# Test TLS connection
openssl s_client -connect minio.example.com:443 -servername minio.example.com

# Check certificate expiry
echo | openssl s_client -connect minio.example.com:443 2>/dev/null | openssl x509 -noout -dates
```

### 4. Verify Manifest Exists

```bash
# Check manifest location
aws s3 ls s3://fraud-gov-artifacts/rulesets/CARD_AUTH/ --endpoint-url $S3_ENDPOINT_URL

# Download manifest to verify content
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json - \
  --endpoint-url $S3_ENDPOINT_URL | jq
```

---

## Resolution

### Connectivity Issues

#### MinIO Container Not Running

```bash
# Start MinIO (from rule-management project)
cd ../card-fraud-rule-management
uv run objstore-local-up
```

#### Network Issues

```bash
# Check DNS resolution
nslookup minio.example.com

# Check network connectivity
telnet minio.example.com 9000
```

### Credential Issues

```bash
# Refresh credentials in Doppler
doppler secrets set S3_ACCESS_KEY_ID=<new-key> --project=card-fraud-rule-engine --config=local
doppler secrets set S3_SECRET_ACCESS_KEY=<new-secret> --project=card-fraud-rule-engine --config=local

# Restart engine to pick up new credentials
kubectl rollout restart deployment fraud-engine -n fraud-engine
```

### TLS Issues

```bash
# If certificate expired, renew it
# If self-signed, ensure engine trusts the CA

# For local development with self-signed certs
export AWS_CA_BUNDLE=/path/to/ca-bundle.crt
```

### Missing Manifest

```bash
# If manifest doesn't exist, publish from rule-management
cd ../card-fraud-rule-management
uv run publish-ruleset --ruleset CARD_AUTH --version v1
```

### Post-Recovery Verification

```bash
# Force manifest refresh
curl -X POST http://localhost:8081/v1/evaluate/rulesets/load \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey": "CARD_AUTH"}'

# Verify ruleset loaded
curl -s http://localhost:8081/v1/manage/rulesets/status | jq
```

---

## Prevention

1. **High Availability:**
   - Use redundant S3/MinIO deployment
   - Configure multi-region replication for artifacts

2. **Monitoring:**
   - Alert on manifest fetch failures
   - Monitor S3 endpoint health

3. **Credentials:**
   - Rotate credentials regularly
   - Use short-lived credentials where possible

4. **TLS:**
   - Monitor certificate expiration
   - Automate certificate renewal

---

## Escalation

| Level | Contact | Criteria |
|-------|---------|----------|
| L1 | On-call SRE | Initial investigation, restarts |
| L2 | Platform Team | S3/MinIO infrastructure issues |
| L3 | Fraud Engineering | Manifest content or format issues |

**Escalate to L2 if:**
- S3/MinIO service is down
- Credential or certificate issues
- Network connectivity problems

**Escalate to L3 if:**
- Manifest content is invalid
- Publishing pipeline issues

---

## How to Reproduce

### Test Scenario 1: MinIO/S3 Down

```bash
# Stop MinIO container
docker stop card-fraud-rule-management-minio

# Attempt ruleset reload
curl -X POST http://localhost:8081/v1/evaluate/rulesets/hotswap \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH","version":"latest"}'

# Observe manifest fetch failure in logs
grep "Failed to fetch manifest" /var/log/fraud-engine/app.log
```

### Test Scenario 2: Wrong Credentials

```bash
# Temporarily set wrong credentials
export S3_ACCESS_KEY_ID=wrong-key
export S3_SECRET_ACCESS_KEY=wrong-secret

# Attempt ruleset operation
curl -X POST http://localhost:8081/v1/evaluate/rulesets/load \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH"}'

# Observe AccessDenied errors
```

### Test Scenario 3: Network Connectivity

```bash
# Block S3 endpoint port
iptables -A INPUT -p tcp --dport 9000 -j DROP

# Attempt ruleset operation
curl -X POST http://localhost:8081/v1/evaluate/rulesets/load \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH"}'

# Observe connection errors

# Restore
iptables -D INPUT -p tcp --dport 9000 -j DROP
```

---

## How to Verify Fix

### 1. Verify S3 Connectivity

```bash
# List bucket
aws s3 ls s3://fraud-gov-artifacts/ --endpoint-url $S3_ENDPOINT_URL
# Expected: Lists bucket contents successfully

# Test credentials
aws s3api head-bucket --bucket fraud-gov-artifacts --endpoint-url $S3_ENDPOINT_URL
# Expected: No errors
```

### 2. Verify Manifest Fetch Works

```bash
# Download manifest
aws s3 cp s3://fraud-gov-artifacts/rulesets/CARD_AUTH/manifest.json - \
  --endpoint-url $S3_ENDPOINT_URL | jq
# Expected: Valid JSON with checksum and version fields

# Test via API
curl -X POST http://localhost:8081/v1/evaluate/rulesets/load \
  -H "Content-Type: application/json" \
  -d '{"rulesetKey":"CARD_AUTH"}'
# Expected: HTTP 200, ruleset loaded
```

### 3. Verify No Fetch Errors

```bash
# Check metrics
curl -s http://localhost:8081/q/metrics | grep manifest_fetch
# Expected: No increases after fix

# Check logs
grep "Failed to fetch manifest\|AccessDenied\|connection refused" /var/log/fraud-engine/app.log
# Expected: No recent entries
```

### 4. Verify Rulesets Loaded

```bash
# Check status
curl -s http://localhost:8081/v1/manage/rulesets/status | jq
# Expected: All rulesets show loaded=true, status=OK

# Test evaluation
curl -X POST http://localhost:8081/v1/evaluate/auth \
  -H "Content-Type: application/json" \
  -d '{"transaction_id":"verify-manifest-001","card_hash":"test","amount":50.00,"currency":"USD"}'
# Expected: decision made, not FAIL_OPEN due to manifest issues
```

---

## Alerting Configuration

### Prometheus Rules

```yaml
groups:
  - name: manifest-alerts
    rules:
      - alert: ManifestFetchFailure
        expr: increase(manifest_fetch_errors_total[5m]) > 0
        for: 0s
        labels:
          severity: warning
        annotations:
          summary: "Manifest fetch failures detected"
          description: "{{ $value }} manifest fetch failures"

      - alert: S3ConnectionProblem
        expr: increase(s3_connection_errors_total[5m]) > 0
        for: 0s
        labels:
          severity: warning
        annotations:
          summary: "S3 connection errors"
          description: "{{ $value }} S3 connection errors detected"

      - alert: AllRulesetsUnloaded
        expr: sum(ruleset_loaded) == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "All rulesets unloaded"
          description: "No rulesets loaded - engine operating in fail-open mode"
```

### Datadog Monitors

```json
{
  "name": "Manifest Fetch Health",
  "type": "metric alert",
  "query": "avg(last_5m):max:manifest_fetch_errors_total > 0",
  "message": "Manifest fetch failures detected. Check S3/MinIO health.",
  "tags": ["service:card-fraud-rule-engine", "component:s3"],
  "priority": 2
}
```

---

## Related Documentation

- [Checksum Mismatch Runbook](./checksum-mismatch.md)
- [Ruleset Reload Loop Runbook](./ruleset-reload-loop.md)
