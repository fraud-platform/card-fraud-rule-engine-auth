package com.fraud.engine.outbox;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;

/**
 * Payload stored in the Redis Streams outbox.
 * Contains the AUTH decision and the original transaction needed to run MONITORING.
 */
public class OutboxEvent {

    private final TransactionContext transaction;
    private final Decision authDecision;

    @JsonCreator
    public OutboxEvent(
            @JsonProperty("transaction") TransactionContext transaction,
            @JsonProperty("authDecision") Decision authDecision) {
        this.transaction = transaction;
        this.authDecision = authDecision;
    }

    public TransactionContext getTransaction() {
        return transaction;
    }

    public Decision getAuthDecision() {
        return authDecision;
    }
}
