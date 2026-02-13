# Load Testing Notes (local scratch, do not commit)

- 2026-02-04: capped rule-engine container to 1 CPU / 1 GiB via docker-compose.override.local.yml (platform repo).
- Kafka publish currently synchronous; expect 10-30 ms overhead. Consider async fire-and-forget for perf tests.
- Locust aggressive spawn caused earlier stalls; using gentle ramp (10/s) for baselines.



## TODO for 2026-02-05 (local, do not commit)
  - Recreate rule-engine with Doppler compose after the change.
- Reload rulesets after restart (bulk-load CARD_AUTH + CARD_MONITORING).
- Smokes (100 users, spawn 10/s, 2m, 1 CPU / 1 GiB):
  - Record p50/p95/p99, error rate, CPU/mem.
- If p50 still high: add load-test flag to make Kafka publish fire-and-forget for latency baselines; measure delta.
- If CPU remains saturated: try 2-core limit or reduce user count for baseline; note scaling behavior for 1k target.
- Once smokes are clean: attempt 1k TPS using gentler ramp or distributed Locust workers; only after baselines stabilized.



## TODO: Auth bypass + reliable async publish (local scratch, do not commit)
- Kafka path: replace current direct producer with outbox-backed async dispatcher (default on, no fallback). Use idempotent producer (`acks=all`, `enable.idempotence=true`, `linger.ms=5`, `batch.size=16384`, `compression=lz4`, bounded retries) and a bounded outbox (Redis list or in-memory for tests). Dispatcher drains with small budget; on failure, leave in queue and retry with backoff; expose queue depth/lag metrics.
- Backpressure: cap backlog by duration (e.g., 60s * target TPS) and fail fast with a specific error code if full; alert when depth exceeds threshold.
- Storage sizing note: keep payload minimal (decision envelope + compact context). Estimate: ~1-2 KB/event JSON; at 1k TPS with 60s buffer ~60-120 MB; at 10k TPS ~0.6-1.2 GB; LZ4 on Redis values typically cuts 40-60%. Consider truncating large context fields or hashing bulky blobs before enqueue.
