# Kafka Producer Optimization (Worker Path)

**Purpose:** Producer tuning for decision events emitted by the monitoring worker (Redis Streams outbox) per ADR-0014. AUTH request latency is isolated, so producer settings can prioritize durability.

**Last Updated:** 2026-02-06

## Problem Statement

Decision events for AUTH traffic are published from the outbox worker.  
We need zero-loss delivery, good batching, and bounded send behavior without adding latency to AUTH API responses.

## Optimized Producer Settings

| Setting | Value | Rationale |
|---------|-------|-----------|
| `enable.idempotence` | `true` | Prevent duplicates on retry |
| `acks` | `all` | Require leader plus replicas |
| `max.in.flight.requests.per.connection` | `5` | Preserve ordering with idempotence |
| `batch.size` | `16384` | Good default for small decision payloads |
| `linger.ms` | `5` | Better batching on worker path |
| `compression.type` | `lz4` | Fast compression and lower network cost |
| `delivery.timeout.ms` | `15000` | Bound send time |
| `retries` | `2147483647` | Retry until success (idempotent producer) |
| `retry.backoff.ms` | `50` | Fast retry cadence |

## Configuration (Current)

```yaml
mp:
  messaging:
    outgoing:
      decision-events:
        connector: smallrye-kafka
        topic: fraud.card.decisions.v1
        bootstrap.servers: ${KAFKA_BOOTSTRAP_SERVERS:localhost:9092}
        key.serializer: org.apache.kafka.common.serialization.StringSerializer
        value.serializer: org.apache.kafka.common.serialization.StringSerializer
        enable.idempotence: true
        acks: all
        max.in.flight.requests.per.connection: 5
        batch.size: 16384
        linger.ms: 5
        compression.type: lz4
        delivery.timeout.ms: 15000
        retries: 2147483647
        retry.backoff.ms: 50
```

`%test` and `%load-test` profiles should mirror these settings so durability failures appear in CI and load runs.

## Trade-offs

- `linger.ms=5` adds batching delay in worker path, not AUTH path.
- `acks=all` plus idempotence increases broker round-trips compared with `acks=1`.
- LZ4 adds modest CPU cost but usually reduces bandwidth materially.

## Monitoring

Track:

- `kafka.producer.record-send-rate`
- `kafka.producer.record-error-rate`
- `kafka.producer.request-latency-avg`
- `redis.pending.entries`
- `redis.oldest.pending.age`
- `monitoring.rules.ms`
- `kafka.publish.ms`

## Validation

1. Run worker with configured producer settings.
2. Stop Kafka temporarily; verify Redis stream backlog grows.
3. Restore Kafka; verify backlog drains and no dropped events.
4. Verify AUTH latency distribution is unchanged.

## References

- ADR-0014
- Quarkus Kafka Guide
- Kafka Producer Configs
