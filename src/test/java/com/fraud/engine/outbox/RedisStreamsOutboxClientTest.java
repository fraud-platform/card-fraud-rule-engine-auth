package com.fraud.engine.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.redis.client.RedisAPI;
import io.vertx.mutiny.redis.client.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.reflect.Field;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RedisStreamsOutboxClientTest {

    @Mock
    RedisAPI redisAPI;

    @Mock
    Response xaddResponse;

    @Mock
    Response xreadResponse;

    private RedisStreamsOutboxClient client;

    @BeforeEach
    void setUp() throws Exception {
        client = new RedisStreamsOutboxClient();
        setField(client, "mode", "redis");
        setField(client, "streamKey", "fraud:outbox");
        setField(client, "consumerGroup", "auth-monitoring-worker");
        setField(client, "consumerName", "worker-1");
        setField(client, "maxLen", 200000L);
        setField(client, "readCount", 50);
        setField(client, "blockMs", 2000);
        setField(client, "redisTimeoutSeconds", 5);
        setField(client, "redisAPI", redisAPI);
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        setField(client, "objectMapper", mapper);
        when(redisAPI.xgroup(anyList())).thenReturn(Uni.createFrom().nullItem());
        client.init();
    }

    @Test
    void appendIncludesStreamKeyInXaddArguments() {
        when(xaddResponse.toString()).thenReturn("1738829520000-0");
        when(redisAPI.xadd(anyList())).thenReturn(Uni.createFrom().item(xaddResponse));

        OutboxEvent event = new OutboxEvent(transaction("txn-1"), decision("txn-1"));
        String id = client.append(event);

        ArgumentCaptor<List<String>> captor = ArgumentCaptor.forClass(List.class);
        verify(redisAPI).xadd(captor.capture());
        List<String> args = captor.getValue();

        assertThat(args.get(0)).isEqualTo("fraud:outbox");
        assertThat(args).contains("payload");
        assertThat(id).isEqualTo("1738829520000-0");
    }

    @Test
    void appendWrapsRedisFailuresInOutboxException() {
        when(redisAPI.xadd(anyList())).thenReturn(Uni.createFrom().failure(new RuntimeException("redis down")));

        OutboxEvent event = new OutboxEvent(transaction("txn-2"), decision("txn-2"));

        assertThrows(OutboxException.class, () -> client.append(event));
    }

    @Test
    void readBatchParsesRedisStreamPayloadAndAckSendsXack() throws Exception {
        OutboxEvent event = new OutboxEvent(transaction("txn-read"), decision("txn-read"));
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        String payload = mapper.writeValueAsString(event);

        Response top = mockResponse(1);
        Response stream = mockResponse(2);
        Response messages = mockResponse(1);
        Response message = mockResponse(2);
        Response fields = mockResponse(2);
        Response fieldName = mockResponse(0);
        Response fieldValue = mockResponse(0);
        Response entryId = mockResponse(0);

        when(top.get(0)).thenReturn(stream);
        when(stream.get(1)).thenReturn(messages);
        when(messages.get(0)).thenReturn(message);
        when(message.get(0)).thenReturn(entryId);
        when(message.get(1)).thenReturn(fields);
        when(fields.get(0)).thenReturn(fieldName);
        when(fields.get(1)).thenReturn(fieldValue);
        when(fieldName.toString()).thenReturn("payload");
        when(fieldValue.toString(java.nio.charset.StandardCharsets.UTF_8)).thenReturn(payload);
        when(entryId.toString()).thenReturn("1738829520000-1");
        when(redisAPI.xreadgroup(anyList())).thenReturn(Uni.createFrom().item(top));
        when(redisAPI.xack(anyList())).thenReturn(Uni.createFrom().nullItem());

        List<OutboxEntry> entries = client.readBatch();

        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).getId()).isEqualTo("1738829520000-1");
        assertThat(entries.get(0).getEvent().getTransaction().getTransactionId()).isEqualTo("txn-read");

        client.ack(entries.get(0).getId());
        verify(redisAPI).xack(anyList());
    }

    @Test
    void readBatchReturnsEmptyOnRedisFailure() {
        when(redisAPI.xreadgroup(anyList())).thenReturn(Uni.createFrom().failure(new RuntimeException("read failed")));

        List<OutboxEntry> entries = client.readBatch();

        assertThat(entries).isEmpty();
    }

    @Test
    void readBatchReturnsEmptyWhenPayloadFieldMissing() {
        Response top = mockResponse(1);
        Response stream = mockResponse(2);
        Response messages = mockResponse(1);
        Response message = mockResponse(2);
        Response fields = mockResponse(2);
        Response fieldName = mockResponse(0);
        Response fieldValue = mockResponse(0);
        Response entryId = mockResponse(0);

        when(top.get(0)).thenReturn(stream);
        when(stream.get(1)).thenReturn(messages);
        when(messages.get(0)).thenReturn(message);
        when(message.get(0)).thenReturn(entryId);
        when(message.get(1)).thenReturn(fields);
        when(fields.get(0)).thenReturn(fieldName);
        when(fieldName.toString()).thenReturn("other");
        when(entryId.toString()).thenReturn("1-0");
        when(redisAPI.xreadgroup(anyList())).thenReturn(Uni.createFrom().item(top));

        assertThat(client.readBatch()).isEmpty();
    }

    private static TransactionContext transaction(String txnId) {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionId(txnId);
        tx.setTransactionType("AUTHORIZATION");
        return tx;
    }

    private static Decision decision(String txnId) {
        Decision decision = new Decision(txnId, "AUTH");
        decision.setDecision(Decision.DECISION_APPROVE);
        return decision;
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static Response mockResponse(int size) {
        Response response = org.mockito.Mockito.mock(Response.class);
        lenient().when(response.size()).thenReturn(size);
        return response;
    }
}
