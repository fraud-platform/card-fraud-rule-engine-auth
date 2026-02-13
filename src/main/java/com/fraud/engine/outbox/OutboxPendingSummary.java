package com.fraud.engine.outbox;

/**
 * Summary of pending entries in the Redis Streams outbox.
 */
public class OutboxPendingSummary {

    private final long totalPending;
    private final long oldestIdleMs;

    public OutboxPendingSummary(long totalPending, long oldestIdleMs) {
        this.totalPending = totalPending;
        this.oldestIdleMs = oldestIdleMs;
    }

    public long getTotalPending() {
        return totalPending;
    }

    public long getOldestIdleMs() {
        return oldestIdleMs;
    }
}
