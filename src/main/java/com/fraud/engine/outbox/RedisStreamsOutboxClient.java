package com.fraud.engine.outbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import io.vertx.mutiny.redis.client.RedisAPI;
import io.vertx.mutiny.redis.client.Response;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import com.fraud.engine.util.EngineMetrics;

/**
 * Redis Streams based outbox for AUTH -> MONITORING handoff.
 */
@ApplicationScoped
@jakarta.inject.Named("redis-outbox")
public class RedisStreamsOutboxClient implements OutboxClient {

    private static final Logger LOG = Logger.getLogger(RedisStreamsOutboxClient.class);

    @ConfigProperty(name = "app.outbox.mode", defaultValue = "redis")
    String mode;

    @ConfigProperty(name = "app.outbox.stream-key", defaultValue = "fraud:outbox")
    String streamKey;

    @ConfigProperty(name = "app.outbox.consumer-group", defaultValue = "auth-monitoring-worker")
    String consumerGroup;

    @ConfigProperty(name = "app.outbox.consumer-name", defaultValue = "worker-1")
    String consumerName;

    @ConfigProperty(name = "app.outbox.maxlen", defaultValue = "200000")
    long maxLen;

    @ConfigProperty(name = "app.outbox.read-count", defaultValue = "50")
    int readCount;

    @ConfigProperty(name = "app.outbox.block-ms", defaultValue = "2000")
    int blockMs;

    @ConfigProperty(name = "app.outbox.redis-timeout-seconds", defaultValue = "5")
    int redisTimeoutSeconds;

    @Inject
    RedisAPI redisAPI;

    @Inject
    ObjectMapper objectMapper;

    @Inject
    EngineMetrics engineMetrics;

    private ObjectWriter outboxEventWriter;
    private String maxLenValue;

    @PostConstruct
    void init() {
        outboxEventWriter = objectMapper.writerFor(OutboxEvent.class);
        maxLenValue = String.valueOf(maxLen);
        if (!isActive()) {
            return;
        }
        ensureConsumerName();
        ensureGroup();
    }

    private void ensureConsumerName() {
        if (consumerName == null) {
            consumerName = "";
        }
        String normalized = consumerName.trim();
        if (normalized.isEmpty() || "worker-1".equalsIgnoreCase(normalized) || "auto".equalsIgnoreCase(normalized)) {
            consumerName = "worker-" + UUID.randomUUID();
        } else {
            consumerName = normalized;
        }
    }

    @Override
    public void ensureGroup() {
        if (!isActive()) {
            return;
        }
        try {
            redisAPI.xgroup(List.of("CREATE", streamKey, consumerGroup, "$", "MKSTREAM"))
                    .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
            LOG.infof("Created Redis Stream group: %s on %s", consumerGroup, streamKey);
        } catch (Exception e) {
            if (e.getMessage() != null && e.getMessage().contains("BUSYGROUP")) {
                LOG.debugf("Redis group already exists: %s", consumerGroup);
            } else {
                LOG.warnf(e, "Failed to create Redis Stream group: %s", consumerGroup);
            }
        }
    }

    @Override
    public String append(OutboxEvent event) {
        if (!isActive()) {
            return null;
        }
        try {
            String payload = outboxEventWriter.writeValueAsString(event);
            List<String> args = new ArrayList<>(7);
            args.add(streamKey);
            args.add("MAXLEN");
            args.add("~");
            args.add(maxLenValue);
            args.add("*");
            args.add("payload");
            args.add(payload);

            Response response = redisAPI.xadd(args)
                    .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
            String id = response != null ? response.toString() : null;

            if (engineMetrics != null) {
                engineMetrics.incrementOutboxXaddSuccess();
            }
            return id;
        } catch (Exception e) {
            if (engineMetrics != null) {
                engineMetrics.incrementOutboxXaddFailure();
            }
            throw new OutboxException("Failed to append to Redis Stream", e);
        }
    }

    @Override
    public List<OutboxEntry> readBatch() {
        if (!isActive()) {
            return Collections.emptyList();
        }
        try {
            List<String> args = new ArrayList<>();
            args.add("GROUP");
            args.add(consumerGroup);
            args.add(consumerName);
            args.add("COUNT");
            args.add(String.valueOf(readCount));
            args.add("BLOCK");
            args.add(String.valueOf(blockMs));
            args.add("STREAMS");
            args.add(streamKey);
            args.add(">");

            // Add extra buffer for BLOCK timeout + network round-trip
            Duration timeout = Duration.ofMillis(blockMs).plus(Duration.ofSeconds(redisTimeoutSeconds));
            Response resp = redisAPI.xreadgroup(args)
                    .await().atMost(timeout);
            if (resp == null) {
                return Collections.emptyList();
            }
            return parseXReadResponse(resp);
        } catch (Exception e) {
            LOG.errorf(e, "Failed to read from Redis Stream");
            return Collections.emptyList();
        }
    }

    @Override
    public List<OutboxEntry> claimPendingBatch(long minIdleMs, int count) {
        if (!isActive()) {
            return Collections.emptyList();
        }
        try {
            List<String> args = new ArrayList<>();
            args.add(streamKey);
            args.add(consumerGroup);
            args.add(consumerName);
            args.add(String.valueOf(minIdleMs));
            args.add("0-0");
            args.add("COUNT");
            args.add(String.valueOf(count));

            Response resp = redisAPI.xautoclaim(args)
                    .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
            if (resp == null || resp.size() < 2) {
                return Collections.emptyList();
            }
            Response messages = resp.get(1);
            if (messages == null) {
                return Collections.emptyList();
            }
            return parseXAutoClaimResponse(messages);
        } catch (Exception e) {
            LOG.warnf(e, "Failed to claim pending outbox entries");
            return Collections.emptyList();
        }
    }

    @Override
    public OutboxPendingSummary pendingSummary() {
        if (!isActive()) {
            return new OutboxPendingSummary(0, 0);
        }
        try {
            Response resp = redisAPI.xpending(List.of(streamKey, consumerGroup))
                    .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
            if (resp == null || resp.size() == 0) {
                return new OutboxPendingSummary(0, 0);
            }
            long totalPending = parseLong(resp.get(0), 0);
            long oldestIdleMs = 0;
            if (totalPending > 0) {
                Response detail = redisAPI.xpending(List.of(streamKey, consumerGroup, "-", "+", "1"))
                        .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
                if (detail != null && detail.size() > 0) {
                    Response first = detail.get(0);
                    if (first != null && first.size() >= 3) {
                        oldestIdleMs = parseLong(first.get(2), 0);
                    }
                }
            }
            return new OutboxPendingSummary(totalPending, oldestIdleMs);
        } catch (Exception e) {
            LOG.debugf(e, "Failed to read pending outbox summary");
            return new OutboxPendingSummary(0, 0);
        }
    }

    @Override
    public void ack(String entryId) {
        if (!isActive()) {
            return;
        }
        try {
            redisAPI.xack(List.of(streamKey, consumerGroup, entryId))
                    .await().atMost(Duration.ofSeconds(redisTimeoutSeconds));
        } catch (Exception e) {
            LOG.warnf(e, "Failed to ack entry %s", entryId);
        }
    }

    private List<OutboxEntry> parseXReadResponse(Response resp) {
        List<OutboxEntry> entries = new ArrayList<>();
        // Response structure: [[stream, [[id, [field, value]...], ...]]]
        for (int i = 0; i < resp.size(); i++) {
            Response streamResp = resp.get(i);
            if (streamResp == null || streamResp.size() < 2) {
                continue;
            }
            Response messages = streamResp.get(1);
            for (int j = 0; j < messages.size(); j++) {
                Response message = messages.get(j);
                String id = message.get(0).toString();
                Response fields = message.get(1);
                Optional<String> payloadOpt = extractPayload(fields);
                payloadOpt.flatMap(this::deserializeEvent)
                        .ifPresent(evt -> entries.add(new OutboxEntry(id, evt)));
            }
        }
        return entries;
    }

    private List<OutboxEntry> parseXAutoClaimResponse(Response messages) {
        List<OutboxEntry> entries = new ArrayList<>();
        for (int j = 0; j < messages.size(); j++) {
            Response message = messages.get(j);
            if (message == null || message.size() < 2) {
                continue;
            }
            String id = message.get(0).toString();
            Response fields = message.get(1);
            Optional<String> payloadOpt = extractPayload(fields);
            payloadOpt.flatMap(this::deserializeEvent)
                    .ifPresent(evt -> entries.add(new OutboxEntry(id, evt)));
        }
        return entries;
    }

    private Optional<String> extractPayload(Response fields) {
        if (fields == null) {
            return Optional.empty();
        }
        for (int k = 0; k < fields.size(); k += 2) {
            if (k + 1 >= fields.size()) {
                break;
            }
            Response fieldName = fields.get(k);
            if (fieldName != null && "payload".equals(fieldName.toString())) {
                Response value = fields.get(k + 1);
                if (value != null) {
                    return Optional.of(value.toString(StandardCharsets.UTF_8));
                }
            }
        }
        return Optional.empty();
    }

    private Optional<OutboxEvent> deserializeEvent(String json) {
        try {
            return Optional.of(objectMapper.readValue(json, OutboxEvent.class));
        } catch (Exception e) {
            LOG.warnf(e, "Failed to deserialize outbox payload");
            return Optional.empty();
        }
    }

    private long parseLong(Response response, long fallback) {
        if (response == null) {
            return fallback;
        }
        try {
            return Long.parseLong(response.toString());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private boolean isActive() {
        return "redis".equalsIgnoreCase(mode);
    }
}
