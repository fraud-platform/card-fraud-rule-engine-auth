# PowerShell Load Testing Runbook

Purpose: avoid repeating the same shell/debug issues across sessions and provide a copy-safe path for distributed AUTH-only runs on Windows.

Date captured: `2026-02-12`

## Scope

- Host shell: Windows PowerShell
- Service under test: `card-fraud-rule-engine` (via `card-fraud-platform` compose)
- Load generator: `card-fraud-e2e-load-testing` with Locust master + workers

## Known PowerShell Failure Modes (And Fixes)

1. Nested quoting breaks `foreach`, `if`, and hash literals
- Symptom: `Missing variable name after foreach`, `Missing condition in if`, hash literal parser errors.
- Cause: double parsing when using nested `powershell.exe -Command "..."` with unescaped quotes.
- Fix:
  - Prefer direct commands in the current shell when possible.
  - If wrapping with `-Command`, use a single-quoted script body and only double-quote inside it.

2. CSV columns with spaces parse incorrectly
- Symptom: expression/parser errors or zeros for metrics.
- Cause: using `$row.Average Response Time` style access.
- Fix: use quoted property names, for example:
  - `$row.'Request Count'`
  - `$row.'Average Response Time'`
  - `$row.'95%'`
  - `$row.'99%'`
  - `$row.'Requests/s'`

3. Unix helpers (`head`) are not available in PowerShell by default
- Symptom: `head : The term 'head' is not recognized`.
- Fix:
  - Use `Select-Object -First N` on host PowerShell.
  - Or run unix tools inside container shell (`docker exec ... sh -lc "... | head -40"`).

4. JFR in container gets overwritten after restart
- Symptom: latest `/tmp/flight.jfr` no longer matches run you want.
- Fix:
  - Copy immediately after each test cycle:
    - `docker cp card-fraud-rule-engine:/tmp/flight.jfr docs/04-testing/<name>.jfr`

5. JFR accidentally left ON during baseline runs
- Symptom: container logs show startup JFR recording and latency matrix drifts from prior non-JFR baselines.
- Cause: platform compose sets `JAVA_JFR_OPTS` by default.
- Fix:
  - For non-profiling baselines, explicitly clear JFR in override:
    - `testing/compose-auth-no-async.override.yml` with `JAVA_JFR_OPTS=`
  - Recreate service after override changes:
    - `doppler run -- docker compose -f docker-compose.yml -f docker-compose.apps.yml -f ../card-fraud-rule-engine/testing/compose-auth-no-async.override.yml -p card-fraud-platform up -d --force-recreate rule-engine`

6. Docker Desktop engine pipe unavailable (`dockerDesktopLinuxEngine`)
- Symptom: `failed to connect to the docker API ... dockerDesktopLinuxEngine`.
- Cause: Docker Desktop backend hangs/restarts.
- Fix:
  - Restart Docker Desktop app.
  - If needed, kill/restart `Docker Desktop` and `com.docker.backend` processes.
  - Re-check with `docker version` before load runs.

7. Locust worker spawn/report mismatch
- Symptom:
  - `Spawning is complete ... not all reports received from workers`
  - `Worker ... failed to send heartbeat`
- Impact: run is non-acceptance quality.
- Fix:
  - mark run as diagnostic-only
  - rerun the same test point until worker mismatch warnings disappear.

8. Manual distributed `run-summary-*.json` may be wrong
- Symptom: `run-summary` shows `0`, `1`, or very low request counts while console and CSV show full run.
- Cause: summary generation path is not reliable for manual master/worker commands in this setup.
- Fix:
  - use `rule-engine-distributed_stats.csv` aggregated row as the acceptance source.
  - keep `run-summary` only as a secondary artifact.

9. Stale Locust worker processes contaminate the next run
- Symptom: unexpected worker behavior before startup or mismatched reports.
- Fix:
  - clear stale local workers before a new run:
    - `Get-Process -Name locust -ErrorAction SilentlyContinue | Stop-Process -Force`
  - keep `Stop-Process` cleanup in `finally` blocks.

10. `uv run gen-report` may fail on Windows codepage (`cp1252`)
- Symptom: `UnicodeEncodeError` while writing markdown report, even though HTML is generated.
- Cause: report writer includes unicode symbols and writes with default console encoding.
- Fix:
  - primary artifact is still generated at `html-reports/combined/index.html`.
  - for clean script exit, run with UTF-8 environment (`$env:PYTHONUTF8='1'`) or update the reporting script to write with UTF-8.

## Proven Distributed Run Pattern (AUTH-only)

Run from `C:/Users/kanna/github/card-fraud-e2e-load-testing`:

```powershell
$users = 200
$spawn = 20
$ts = Get-Date -Format yyyyMMdd-HHmmss
$runId = "lt-dist-auth-only-u$users-$ts"
$outDir = Join-Path (Get-Location) "html-reports/runs/$runId/locust"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

$env:TEST_RULE_ENGINE = "true"
$env:TEST_TRANSACTION_MGMT = "false"
$env:TEST_RULE_MGMT = "false"
$env:RULE_ENGINE_PREAUTH_WEIGHT = "1.0"
$env:RULE_ENGINE_POSTAUTH_WEIGHT = "0.0"
$env:RULE_ENGINE_URL = "http://localhost:8081"

$workerArgs = @(
  "run", "locust",
  "-f", "src/locustfile.py",
  "--worker",
  "--master-host", "127.0.0.1",
  "--master-port", "5557"
)

$w1 = Start-Process uv -ArgumentList $workerArgs -PassThru -WindowStyle Hidden -WorkingDirectory (Get-Location) `
  -RedirectStandardOutput (Join-Path $outDir "worker1.log") `
  -RedirectStandardError (Join-Path $outDir "worker1.err.log")
$w2 = Start-Process uv -ArgumentList $workerArgs -PassThru -WindowStyle Hidden -WorkingDirectory (Get-Location) `
  -RedirectStandardOutput (Join-Path $outDir "worker2.log") `
  -RedirectStandardError (Join-Path $outDir "worker2.err.log")

Start-Sleep -Seconds 6
try {
  uv run locust -f src/locustfile.py `
    --master --master-bind-host 127.0.0.1 --master-port 5557 --expect-workers 2 `
    --headless --users $users --spawn-rate $spawn --run-time 2m `
    --html (Join-Path $outDir "rule-engine-distributed.html") `
    --csv (Join-Path $outDir "rule-engine-distributed")
} finally {
  Stop-Process -Id $w1.Id,$w2.Id -Force -ErrorAction SilentlyContinue
}
```

## Proven Metrics Extraction Snippet

```powershell
$csv = "C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/runs/<run-id>/locust/rule-engine-distributed_stats.csv"
$row = Import-Csv $csv | Where-Object { $_.Name -eq "Aggregated" } | Select-Object -First 1

[pscustomobject]@{
  requests = [int]$row.'Request Count'
  failures = [int]$row.'Failure Count'
  p50_ms = [double]$row.'50%'
  avg_ms = [Math]::Round([double]$row.'Average Response Time', 2)
  p95_ms = [double]$row.'95%'
  p99_ms = [double]$row.'99%'
  max_ms = [double]$row.'Max Response Time'
  rps = [Math]::Round([double]$row.'Requests/s', 2)
}
```

## Session Handoff Checklist (Before Pause)

1. Save run IDs and final metrics in `docs/04-testing/load-testing-baseline.md`.
2. Copy latest JFR from container to a timestamped file under `docs/04-testing/`.
3. Save any extracted JFR text (`exec`, `alloc`, `gc`) next to the JFR file.
4. Record ON vs OFF mode explicitly for each run (`AUTH_ASYNC_DURABILITY_ENABLED`, `OUTBOX_AUTH_PUBLISHER_ENABLED`).
5. Confirm artifact root path:
  - `C:/Users/kanna/github/card-fraud-e2e-load-testing/html-reports/runs/`
6. Reject runs with worker heartbeat/spawn mismatch for acceptance reporting.
7. Prefer CSV aggregated metrics over `run-summary-*.json` for manual distributed runs.

## Verified Artifacts From This Session

- Async ON JFR:
  - `docs/04-testing/flight-20260210-2158-postfix-async-on-200-jfr.jfr`
- Async OFF JFR:
  - `docs/04-testing/flight-20260210-2208-postfix-async-off-200-jfr.jfr`
- Async OFF extracted files:
  - `docs/04-testing/flight-20260210-2208-postfix-async-off-200-exec.txt`
  - `docs/04-testing/flight-20260210-2208-postfix-async-off-200-alloc.txt`
  - `docs/04-testing/flight-20260210-2208-postfix-async-off-200-gc.txt`

## Latest Run IDs (2026-02-12)

- 200 users OFF:
  - `lt-dist-lazyctx-lazytimestamp-async-off-u200-20260212-055446`
- 200 users ON:
  - `lt-dist-lazyctx-lazytimestamp-async-on-u200-20260212-060144`
- 100 users OFF (clean rerun):
  - `lt-dist-lazyctx-lazytimestamp-async-off-u100-rerun-20260212-064654`
- 100 users ON:
  - `lt-dist-lazyctx-lazytimestamp-async-on-u100-20260212-061959`
- 50 users OFF (clean rerun):
  - `lt-dist-lazyctx-lazytimestamp-async-off-u50-rerun-20260212-065122`
- 50 users ON:
  - `lt-dist-lazyctx-lazytimestamp-async-on-u50-20260212-063137`
- Scope-cache OFF rerun:
  - `lt-dist-scopecache-async-off-u50-rerun-20260212-192456`
- Scope-cache OFF rerun (JFR cleared):
  - `lt-dist-scopecache-nojfr-async-off-u50-20260212-194613`
