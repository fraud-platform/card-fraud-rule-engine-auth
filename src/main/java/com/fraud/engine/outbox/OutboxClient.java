package com.fraud.engine.outbox;

import java.util.List;

public interface OutboxClient {

    /**
     * Appends a new event to the outbox.
     * @return stream entry id
     */
    String append(OutboxEvent event);

    /**
     * Reads a batch of events for this consumer.
     */
    List<OutboxEntry> readBatch();

    /**
     * Claims and reads a batch of pending events that have been idle.
     */
    List<OutboxEntry> claimPendingBatch(long minIdleMs, int count);

    /**
     * Returns a summary of pending entries (count + oldest idle age).
     */
    OutboxPendingSummary pendingSummary();

    /**
     * Acknowledge a processed entry.
     */
    void ack(String entryId);

    /**
     * Initialize stream/group if needed.
     */
    void ensureGroup();
}
