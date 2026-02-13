# Redis Velocity & Transaction Replay - Technical Decisions

This document covers Redis velocity behavior in the runtime engine and the limitations of transaction replay. Redis also backs the Redis Streams outbox for auth→monitoring (ADR-0014); that flow is documented separately. This file focuses on velocity semantics.

**Important:** Redis-backed velocity is an ONLINE mechanism. True point-in-time replay with historical velocity is currently **deferred**.

## 1. Redis TTL Expiry Mechanism

### How Redis TTL Works

**Q: How does Redis key expiration happen? Is there a background process in the rule engine?**

**A: No background process is needed in the rule engine. Redis handles TTL internally.**

```
┌─────────────────────────────────────────────────────────┐
│                    Redis Server                          │
│  ┌───────────────────────────────────────────────────┐ │
│  │ Key-Value Store with TTL                            │ │
│  │                                                    │ │
│  │  key: "vel:global:card_hash:a1b2c3..."            │ │
│  │  value: 5                                         │ │
│  │  ttl: 3595 seconds remaining                       │ │
│  │                                                    │ │
│  └───────────────────────────────────────────────────┘ │
│  ┌───────────────────────────────────────────────────┐ │
│  │ Internal Background Process (Redis-managed)        │ │
│  │ - Scans for expired keys                           │ │
│  │ - Evicts them from memory                           │ │
│  │ - Runs periodically (lazy + active expiration)      │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Key Points:

1. **No External Process Needed**: Redis has two expiration mechanisms:
   - **Lazy expiration**: Key is checked when accessed; if expired, deleted
   - **Active expiration**: Background cron job runs every 10ms (default) to sample keys and evict expired ones

2. **INCR + EXPIRE Pattern**:
   ```java
   // In VelocityService.incrementAndGet()
   Long count = commands.incr(key);  // Atomic - thread-safe
   if (count == 1) {
       commands.setex(key, windowSeconds, count);  // Set TTL
   }
   ```

3. **Atomicity of INCR**:
   - Redis INCR is **atomic by design** - guaranteed unique values
   - Even 1000 concurrent requests get values 1, 2, 3, ..., 1000
   - No lost updates, no race conditions on the count itself

4. **Expiry Race Condition** (benign):
   - Two requests might both see `count == 1`
   - Both try to SETEX - second one just overwrites (same value)
   - Worst case: key persists slightly longer than window (handled by Redis maxmemory policy)

---

## 2. Transaction Replay and the "Time Travel" Problem

### The Problem

**Q: When we replay a transaction, how do we know what velocity was present in Redis at the original time?**

**A: This is indeed a "time travel" problem. Here's how we handle it:**

```
┌─────────────────────────────────────────────────────────────┐
│                    Timeline                                  │
│  10:00:00  Txn A arrives (velocity count = 5)              │
│  10:00:01  Txn B arrives (velocity count = 6)              │
│  10:00:02  Txn C arrives (velocity count = 7)              │
│  10:05:00  User decides to replay Txn A to test new rules   │
│            What velocity should Txn A see? 5? 7? Something else?│
└─────────────────────────────────────────────────────────────┘
```

### Current Replay Semantics (Best-Effort)

The engine provides replay endpoints for debugging and "what-if" evaluation with **no side effects**.

- Replay can target a specific ruleset version.
- Replay does not publish decision events.
- Replay does not increment Redis velocity counters.

However, replay cannot reconstruct the historical Redis velocity state from the original point in time.

#### Behavior: Read-Only Velocity (Current Implementation)

In **replay mode**, we:
1. **Do NOT increment** the velocity counter
2. **READ** the current velocity value
3. **Flag** the decision with `MODE_REPLAY`

```java
// In ManagementResource.replayTransaction()
Decision decision = ruleEvaluator.evaluate(transaction, ruleset, replayMode=true);

// In RuleEvaluator.evaluateAUTH()
if (replayMode) {
    velocityResult = checkVelocityReadOnly(transaction, rule);  // Read only
} else {
    velocityResult = checkVelocity(transaction, rule);          // Increment
}
```

**Use Cases:**
- Testing rule changes against historical data
- Debugging why a specific decision was made
- "What would this transaction get with the new rules?"

**Limitation (Non-Negotiable):**
- Replay sees **current** Redis velocity, not **historical** velocity.
- If you replay a transaction from an hour ago, you will see the current counter value.
- Redis TTL-based counters are ephemeral and cannot "time travel".

### 2.1 Parked: True Point-in-Time Replay (Deferred)

Supporting point-in-time replay ("evaluate as-of the original transaction timestamp, including velocity") requires a separate design:

- An immutable transaction event log (Kafka retained to S3/warehouse, or similar)
- Reconstructed velocity state (computed from the event log) OR historical aggregates
- A replay mode that never touches production Redis state

This is intentionally deferred because it is operationally and data-wise non-trivial.

### 2.2 Options for Point-in-Time Replay (Future Enhancements)

#### Option A: Event Log + Recompute Velocity (Gold Standard)

During replay/backtest:
- stream transactions in timestamp order
- recompute velocity windows (in memory or in a dedicated replay Redis)
- evaluate rulesets against reconstructed state

#### Option B: Pre-Aggregated Historical Velocity Tables

Maintain an offline store of velocity buckets:

```
velocity_snapshots(
  entityType,
  entityId,
  windowSeconds,
  bucketStart,
  count,
  amount
)
```

Replay queries these instead of Redis.

#### Option C: Hybrid

Recent replay uses raw events; older replay uses aggregates.

### 2.3 Easy Wins (Low Effort) If Replayability Is Needed Soon

These do not provide true time travel, but they materially improve operational usefulness:

1) **Decision envelope includes velocity state at evaluation time**
  - Persist the velocity inputs/results inside the decision event payload.
  - Replay can display "what velocity was observed" for that decision without querying Redis.

2) **Replay runs with velocity disabled**
  - For UI/debug replay, allow a mode that skips velocity evaluation entirely.
  - This makes replay deterministic with respect to rules and transaction fields.

For true time travel, we can store velocity snapshots:

```
┌─────────────────────────────────────────────────────────────┐
│                    Redis Store                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
│  │ vel:card:abc123  │  │ vel:snap:abc123 │  │ vel:hist... │ │
│  │ value: 42        │  │ "10:00:00:42"   │  │             │ │
│  │ ttl: 3599        │  │ ttl: 86400      │  │             │ │
│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
│       Current              Snapshot           History       │
└─────────────────────────────────────────────────────────────┘
```

**Implementation:**
```java
// After velocity check, store snapshot
void recordVelocitySnapshot(String key, long count, Instant timestamp) {
    String snapshotKey = "vel:snap:" + key;
    // Store as "timestamp:count" for easy retrieval
    String value = timestamp.toString() + ":" + count;
    redis.set(snapshotKey, value, Expiration.hours(24));
}
```

**Replay with Snapshot:**
```java
// Get historical velocity
long historicalVelocity = getHistoricalVelocity(transaction, replayTimestamp);
```

#### Option D: Decision Envelope Includes Velocity State (Recommended)

Store the velocity state **in the decision event** itself:

```json
{
  "decision_id": "uuid-123",
  "transaction_id": "txn-456",
  "decision": "DECLINE",
  "velocity_state_at_time": {
    "card_hash_velocity": {
      "count": 7,
      "threshold": 10,
      "exceeded": false
    },
    "amount_velocity": {
      "count": 3,
      "threshold": 5,
      "exceeded": true
    }
  },
  "timestamp": "2026-01-22T10:00:02Z"
}
```

**Benefits:**
- Decision becomes self-contained for replay
- No need to query Redis during replay
- Perfect audit trail

This can be stored in Kafka and queried from transaction-management.

---

## 3. Concurrent Velocity Scenarios

### Scenario: 5 Transactions Arrive Simultaneously

```
Time  Redis (vel:card:abc123)    Txn1        Txn2        Txn3        Txn4        Txn5
─────────────────────────────────────────────────────────────────────────────
t0    value: 0 (doesn't exist)     INCR        INCR        INCR        INCR        INCR
t1    value: 1 (Txn1 wins)        got:1       got:2       got:3       got:4       got:5
t2    value: 5 (final)
t3    EXPIRE 3600                SETEX       (skip)      (skip)      (skip)      (skip)
```

**Result:**
- All 5 transactions get **different, correct values** (1, 2, 3, 4, 5)
- INCR is atomic - no two transactions get the same count
- Velocity works correctly even under high concurrency

### Why This is Correct

1. **Redis INCR is atomic** (single-threaded for each key)
2. **Linearizable** - all clients see consistent ordering
3. **No lost updates** - every increment is counted

---

## 4. Production vs Replay Priority

### Endpoint Design

```
┌──────────────────────────────────────────────────────────────┐
│                    Rule Engine API                            │
│  ┌─────────────────────────────────────────────────────────┐│
│  │ /v1/evaluate/auth   → Production (high priority)     ││
│  │ /v1/evaluate/monitoring  → Production (high priority)     ││
│  └─────────────────────────────────────────────────────────┘│
│  ┌─────────────────────────────────────────────────────────┐│
│  │ /v1/manage/replay       → Replay (lower priority)        ││
│  │ /v1/manage/metrics      → Metrics (lower priority)       ││
│  └─────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────┘
```

### Priority Strategies

**Option A: Rate Limiting (Recommended)**
```yaml
# application.properties
quarkus.limiter.replay.period=1000  # 1 request per second
quarkus.limiter.replay.consumes=10    # Burst capacity
```

**Option B: Separate Request Pool**
```java
// Use different HTTP threads for replay
@ConsumeEvent("replay-queue")
public void handleReplay(ReplayRequest request) {
    // Process replay asynchronously
}
```

**Option C: Client-Side Throttling**
- UI throttles replay requests
- Shows "Replay queued" message during high load

---

## 5. Summary Table

| Question | Answer |
|----------|--------|
| **Redis TTL mechanism?** | Internal Redis process, no rule-engine code needed |
| **Is INCR atomic?** | Yes - Redis INCR is atomic by design |
| **Can 5 concurrent txns bypass velocity?** | No - each gets unique incrementing count |
| **How does replay know historical velocity?** | Current: reads live value. Future: use decision envelope or velocity snapshots |
| **Should replay have lower priority?** | Yes - use rate limiting or separate queue |
| **Do we need separate Locust project?** | Yes - for testing full system (UI + rule-management + rule-engine + transaction-mgmt) |

---

## 6. Recommendations

### Current (Implemented)
1. ✅ Replay mode does not increment velocity (read-only)
2. ✅ Replay endpoint supports ruleset version selection
3. ✅ Redis INCR is atomic and safe under high load

### Next (If Needed)
1. Add velocity state to the decision envelope (audit/debug value)
2. Add a replay flag to disable velocity evaluation for deterministic replay

### Future Enhancements
1. **Add velocity state to decision envelope** (stored in Kafka)
2. **Velocity snapshots** for time-travel replay
3. **Rate limiting** on replay endpoints
4. **Separate Locust project** for full-system testing

---

## 7. Clock Skew Handling

### The Problem

When multiple services are involved in transaction processing, clock skew between servers can affect velocity window accuracy.

**Example:**
- Transaction service: `2026-01-24T10:00:00Z`
- Rule engine: `2026-01-24T09:59:58Z` (2 seconds behind)
- Redis server: `2026-01-24T10:00:05Z` (5 seconds ahead)

### Current Design Decision

**We use Redis server time for velocity windows.**

This means:
- ✅ Velocity windows are consistent (all use Redis time)
- ✅ No dependency on client clock accuracy
- ⚠️ Transaction `occurred_at` timestamp is informational only

### Why This Works

1. **Velocity is about current state** - "How many transactions in the last hour?"
2. **Redis TTL is based on Redis time** - Keys expire based on server clock
3. **Atomic operations** - INCR+EXPIRE happens on Redis server

### Clock Skew Tolerance

| Skew Amount | Impact | Mitigation |
|-------------|--------|------------|
| < 5 seconds | Negligible | None needed |
| 5-30 seconds | Minor window shift | Acceptable for fraud detection |
| > 30 seconds | Consider NTP sync | Configure NTP on all servers |

### Replay Mode Consideration

**When replaying historical transactions:**
- Replay uses current Redis velocity (not historical)
- This is intentional - see Section 2 for details
- For historical analysis, velocity should be disabled in replay

### Configuration

No additional configuration needed. The system automatically:
- Uses Redis server time for all velocity operations
- Treats `occurred_at` as informational metadata

---

## 8. Recommendations

### Current (Implemented)
1. ✅ Replay mode does not increment velocity (read-only)
2. ✅ Replay endpoint supports ruleset version selection
3. ✅ Redis INCR is atomic and safe under high load
4. ✅ Redis server time used for velocity windows

### Next (If Needed)
1. Add velocity state to the decision envelope (audit/debug value)
2. Add a replay flag to disable velocity evaluation for deterministic replay

### Future Enhancements
1. **Add velocity state to decision envelope** (stored in Kafka)
2. **Velocity snapshots** for time-travel replay
3. **Rate limiting** on replay endpoints
4. **Separate Locust project** for full-system testing
