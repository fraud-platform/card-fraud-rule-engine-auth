package com.fraud.engine.outbox;

/**
 * Wrapper representing one stream entry read from the outbox.
 */
public class OutboxEntry {
    private final String id;
    private final OutboxEvent event;

    public OutboxEntry(String id, OutboxEvent event) {
        this.id = id;
        this.event = event;
    }

    public String getId() {
        return id;
    }

    public OutboxEvent getEvent() {
        return event;
    }
}
