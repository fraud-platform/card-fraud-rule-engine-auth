# ADR-0019: Redis Streams Pending Recovery is Required for Retries

**Status:** Accepted  
**Date:** 2026-02-09  
**Owners:** Rule Engine Team  

---

## Context

Redis Streams consumer groups provide at-least-once delivery when used correctly.

However, reading only new messages with:
- `XREADGROUP ... STREAMS <stream> >`

does not automatically retry messages that were delivered but not acknowledged.
Those messages become **pending** for the consumer group.

If the worker crashes or errors after receiving a message but before `XACK`, the message can be stranded indefinitely without explicit pending recovery.

---

## Decision

Any Redis Streams consumer-group based durability pipeline MUST implement pending recovery:

- Prefer `XAUTOCLAIM` to claim stale pending messages and retry processing.
- Alternatively use `XPENDING` summary + `XCLAIM`.

Workers MUST:
- `XACK` only after the downstream side-effect is confirmed (e.g., Kafka publish ack).
- Use unique consumer names per instance.
- Expose metrics for pending counts and oldest pending age.

---

## Failure semantics

- Worker crash: pending messages remain; another worker must reclaim and retry.
- Poison pill: repeated failures must be observable (retry counts, dead-letter strategy if needed).

---

## Consequences

- Adds implementation complexity but is mandatory for correctness.
- Enables operational confidence that “no ack means retry” is true.

---

## Related

- AUTH hot path behavior:
  - [docs/07-reference/0018-auth-hot-path-auth-only-async-durability.md](0018-auth-hot-path-auth-only-async-durability.md)
- Existing outbox ADR:
  - [docs/07-reference/0014-auth-monitoring-redis-streams-outbox.md](0014-auth-monitoring-redis-streams-outbox.md)
