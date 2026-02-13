package com.fraud.engine.outbox;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import org.eclipse.microprofile.config.inject.ConfigProperty;

/**
 * Facade that selects the active OutboxClient implementation based on configuration.
 */
@ApplicationScoped
public class OutboxFacade implements OutboxClient {

    @ConfigProperty(name = "app.outbox.mode", defaultValue = "redis")
    String mode;

    @Inject
    @Named("redis-outbox")
    RedisStreamsOutboxClient redisOutbox;

    @Inject
    @Named("in-memory-outbox")
    InMemoryOutboxClient inMemoryOutbox;

    @PostConstruct
    void init() {
        delegate().ensureGroup();
    }

    private OutboxClient delegate() {
        if ("in-memory".equalsIgnoreCase(mode)) {
            return inMemoryOutbox;
        }
        return redisOutbox;
    }

    @Override
    public String append(OutboxEvent event) {
        return delegate().append(event);
    }

    @Override
    public java.util.List<OutboxEntry> readBatch() {
        return delegate().readBatch();
    }

    @Override
    public java.util.List<OutboxEntry> claimPendingBatch(long minIdleMs, int count) {
        return delegate().claimPendingBatch(minIdleMs, count);
    }

    @Override
    public OutboxPendingSummary pendingSummary() {
        return delegate().pendingSummary();
    }

    @Override
    public void ack(String entryId) {
        delegate().ack(entryId);
    }

    @Override
    public void ensureGroup() {
        delegate().ensureGroup();
    }
}
