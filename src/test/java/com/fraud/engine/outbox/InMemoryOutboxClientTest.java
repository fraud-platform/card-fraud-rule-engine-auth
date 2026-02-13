package com.fraud.engine.outbox;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryOutboxClientTest {

    private InMemoryOutboxClient client;

    @BeforeEach
    void setup() throws Exception {
        client = new InMemoryOutboxClient();
        setField(client, "mode", "in-memory");
        client.init();
    }

    @Test
    void appendAndReadBatch() {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionId("txn-1");
        Decision decision = new Decision("txn-1", "AUTH");
        OutboxEvent event = new OutboxEvent(tx, decision);

        String id = client.append(event);
        assertNotNull(id);

        List<OutboxEntry> entries = client.readBatch();
        assertEquals(1, entries.size());
        assertEquals(id, entries.get(0).getId());
        assertEquals("txn-1", entries.get(0).getEvent().getTransaction().getTransactionId());

        client.ack(id); // should not throw
        assertTrue(client.readBatch().isEmpty(), "queue drains after read");
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }
}
