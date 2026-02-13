package com.fraud.engine.outbox;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Test-friendly, in-memory outbox implementation.
 */
@ApplicationScoped
@jakarta.inject.Named("in-memory-outbox")
public class InMemoryOutboxClient implements OutboxClient {

    @ConfigProperty(name = "app.outbox.mode", defaultValue = "redis")
    String mode;

    private BlockingQueue<OutboxEntry> queue;

    @PostConstruct
    void init() {
        queue = new LinkedBlockingQueue<>();
    }

    @Override
    public String append(OutboxEvent event) {
        if (!isActive()) {
            return null;
        }
        String id = UUID.randomUUID().toString();
        queue.add(new OutboxEntry(id, event));
        return id;
    }

    @Override
    public List<OutboxEntry> readBatch() {
        if (!isActive()) {
            return List.of();
        }
        List<OutboxEntry> batch = new ArrayList<>();
        queue.drainTo(batch);
        return batch;
    }

    @Override
    public List<OutboxEntry> claimPendingBatch(long minIdleMs, int count) {
        return List.of();
    }

    @Override
    public OutboxPendingSummary pendingSummary() {
        return new OutboxPendingSummary(0, 0);
    }

    @Override
    public void ack(String entryId) {
        // no-op for in-memory
    }

    @Override
    public void ensureGroup() {
        // no-op for in-memory
    }

    private boolean isActive() {
        return "in-memory".equalsIgnoreCase(mode);
    }
}
