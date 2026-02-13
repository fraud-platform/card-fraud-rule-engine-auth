package com.fraud.engine.outbox;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class OutboxFacadeTest {

    private OutboxFacade facade;
    private RedisStreamsOutboxClient redisOutbox;
    private InMemoryOutboxClient inMemoryOutbox;

    @BeforeEach
    void setUp() {
        facade = new OutboxFacade();
        redisOutbox = Mockito.mock(RedisStreamsOutboxClient.class);
        inMemoryOutbox = Mockito.mock(InMemoryOutboxClient.class);
        facade.redisOutbox = redisOutbox;
        facade.inMemoryOutbox = inMemoryOutbox;
    }

    @Test
    void delegatesToInMemoryWhenConfigured() {
        facade.mode = "in-memory";
        OutboxEvent event = createEvent("txn-1");
        OutboxEntry entry = new OutboxEntry("1-0", event);
        when(inMemoryOutbox.append(event)).thenReturn("1-0");
        when(inMemoryOutbox.readBatch()).thenReturn(List.of(entry));

        facade.init();
        String id = facade.append(event);
        List<OutboxEntry> entries = facade.readBatch();
        facade.ack("1-0");
        facade.ensureGroup();

        assertThat(id).isEqualTo("1-0");
        assertThat(entries).hasSize(1);
        verify(inMemoryOutbox, times(2)).ensureGroup();
        verify(inMemoryOutbox).append(event);
        verify(inMemoryOutbox).readBatch();
        verify(inMemoryOutbox).ack("1-0");
        verify(redisOutbox, never()).append(any());
    }

    @Test
    void delegatesToRedisByDefault() {
        facade.mode = "redis";
        OutboxEvent event = createEvent("txn-2");
        OutboxEntry entry = new OutboxEntry("2-0", event);
        when(redisOutbox.append(event)).thenReturn("2-0");
        when(redisOutbox.readBatch()).thenReturn(List.of(entry));

        facade.init();
        String id = facade.append(event);
        List<OutboxEntry> entries = facade.readBatch();
        facade.ack("2-0");
        facade.ensureGroup();

        assertThat(id).isEqualTo("2-0");
        assertThat(entries).hasSize(1);
        verify(redisOutbox, times(2)).ensureGroup();
        verify(redisOutbox).append(event);
        verify(redisOutbox).readBatch();
        verify(redisOutbox).ack("2-0");
        verify(inMemoryOutbox, never()).append(any());
    }

    private OutboxEvent createEvent(String txId) {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionId(txId);

        Decision authDecision = new Decision(txId, RuleEvaluator.EVAL_AUTH);
        authDecision.setDecision(Decision.DECISION_APPROVE);
        return new OutboxEvent(tx, authDecision);
    }
}
