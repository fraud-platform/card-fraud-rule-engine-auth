package com.fraud.engine.util;

import jakarta.enterprise.context.ApplicationScoped;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Lightweight in-process counters for engine observability.
 * <p>
 * Exposed via {@code /v1/manage/metrics}. No external dependency required.
 * Can be replaced with Micrometer/OpenTelemetry later.
 */
@ApplicationScoped
public class EngineMetrics {

    private final AtomicLong failOpenTotal = new AtomicLong();
    private final AtomicLong degradedResponseTotal = new AtomicLong();
    private final AtomicLong hotReloadSuccessTotal = new AtomicLong();
    private final AtomicLong hotReloadFailureTotal = new AtomicLong();
    private final AtomicLong startupRulesetFailures = new AtomicLong();
    private final AtomicLong startupRulesetLoadTimeMs = new AtomicLong();

    private final AtomicLong authAsyncDurabilityEnqueuedTotal = new AtomicLong();
    private final AtomicLong authAsyncDurabilityPersistedTotal = new AtomicLong();
    private final AtomicLong authAsyncDurabilityPersistFailuresTotal = new AtomicLong();
    private final AtomicLong authAsyncDurabilityQueueFullDropsTotal = new AtomicLong();
    private final AtomicLong authAsyncDurabilityInvalidDropsTotal = new AtomicLong();
    private final AtomicLong authAsyncDurabilityDisabledDropsTotal = new AtomicLong();
    private final AtomicLong authAsyncEnqueueOkTotal = new AtomicLong();
    private final AtomicLong authAsyncEnqueueDroppedTotal = new AtomicLong();
    private final AtomicLong authAsyncQueueDepth = new AtomicLong();

    private final AtomicLong outboxXaddSuccessTotal = new AtomicLong();
    private final AtomicLong outboxXaddFailureTotal = new AtomicLong();

    private final AtomicLong kafkaPublishSuccessTotal = new AtomicLong();
    private final AtomicLong kafkaPublishFailureTotal = new AtomicLong();
    private final AtomicLong kafkaPublishLatencyMsLast = new AtomicLong();
    private final AtomicLong kafkaPublishLatencyMsTotal = new AtomicLong();
    private final AtomicLong kafkaPublishCountTotal = new AtomicLong();

    private final AtomicLong pendingReclaimedTotal = new AtomicLong();
    private final AtomicLong outboxLagSecondsLast = new AtomicLong();
    private final AtomicLong outboxPendingTotal = new AtomicLong();
    private final AtomicLong outboxPendingOldestIdleMs = new AtomicLong();

    public void incrementFailOpen() {
        failOpenTotal.incrementAndGet();
    }

    public void incrementDegraded() {
        degradedResponseTotal.incrementAndGet();
    }

    public void incrementHotReloadSuccess() {
        hotReloadSuccessTotal.incrementAndGet();
    }

    public void incrementHotReloadFailure() {
        hotReloadFailureTotal.incrementAndGet();
    }

    public void incrementStartupRulesetFailure() {
        startupRulesetFailures.incrementAndGet();
    }

    public void recordStartupLoadTime(long ms) {
        startupRulesetLoadTimeMs.set(ms);
    }

    public void incrementAuthAsyncDurabilityEnqueued() {
        authAsyncDurabilityEnqueuedTotal.incrementAndGet();
    }

    public void incrementAuthAsyncDurabilityPersisted() {
        authAsyncDurabilityPersistedTotal.incrementAndGet();
    }

    public void incrementAuthAsyncDurabilityPersistFailures() {
        authAsyncDurabilityPersistFailuresTotal.incrementAndGet();
    }

    public void incrementAuthAsyncDurabilityQueueFullDrops() {
        authAsyncDurabilityQueueFullDropsTotal.incrementAndGet();
    }

    public void incrementAuthAsyncDurabilityInvalidDrops() {
        authAsyncDurabilityInvalidDropsTotal.incrementAndGet();
    }

    public void incrementAuthAsyncDurabilityDisabledDrops() {
        authAsyncDurabilityDisabledDropsTotal.incrementAndGet();
    }

    public void incrementAuthAsyncEnqueueOk() {
        authAsyncEnqueueOkTotal.incrementAndGet();
    }

    public void incrementAuthAsyncEnqueueDropped() {
        authAsyncEnqueueDroppedTotal.incrementAndGet();
    }

    public void setAuthAsyncQueueDepth(long depth) {
        authAsyncQueueDepth.set(depth);
    }

    public void incrementOutboxXaddSuccess() {
        outboxXaddSuccessTotal.incrementAndGet();
    }

    public void incrementOutboxXaddFailure() {
        outboxXaddFailureTotal.incrementAndGet();
    }

    public void incrementKafkaPublishSuccess(long latencyMs) {
        kafkaPublishSuccessTotal.incrementAndGet();
        kafkaPublishCountTotal.incrementAndGet();
        kafkaPublishLatencyMsLast.set(latencyMs);
        kafkaPublishLatencyMsTotal.addAndGet(latencyMs);
    }

    public void incrementKafkaPublishFailure() {
        kafkaPublishFailureTotal.incrementAndGet();
        kafkaPublishCountTotal.incrementAndGet();
    }

    public void incrementPendingReclaimed(long count) {
        pendingReclaimedTotal.addAndGet(count);
    }

    public void setOutboxLagSeconds(long lagSeconds) {
        outboxLagSecondsLast.set(lagSeconds);
    }

    public void setOutboxPendingSummary(long totalPending, long oldestIdleMs) {
        outboxPendingTotal.set(totalPending);
        outboxPendingOldestIdleMs.set(oldestIdleMs);
    }

    public Map<String, Long> snapshot() {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put("fail_open_total", failOpenTotal.get());
        m.put("degraded_response_total", degradedResponseTotal.get());
        m.put("hot_reload_success_total", hotReloadSuccessTotal.get());
        m.put("hot_reload_failure_total", hotReloadFailureTotal.get());
        m.put("startup_ruleset_failures", startupRulesetFailures.get());
        m.put("startup_ruleset_load_time_ms", startupRulesetLoadTimeMs.get());

        m.put("auth_async_durability_enqueued_total", authAsyncDurabilityEnqueuedTotal.get());
        m.put("auth_async_durability_persisted_total", authAsyncDurabilityPersistedTotal.get());
        m.put("auth_async_durability_persist_failures_total", authAsyncDurabilityPersistFailuresTotal.get());
        m.put("auth_async_durability_queue_full_drops_total", authAsyncDurabilityQueueFullDropsTotal.get());
        m.put("auth_async_durability_invalid_drops_total", authAsyncDurabilityInvalidDropsTotal.get());
        m.put("auth_async_durability_disabled_drops_total", authAsyncDurabilityDisabledDropsTotal.get());
        m.put("auth_async_enqueue_ok_total", authAsyncEnqueueOkTotal.get());
        m.put("auth_async_enqueue_dropped_total", authAsyncEnqueueDroppedTotal.get());
        m.put("auth_async_queue_depth", authAsyncQueueDepth.get());
        m.put("outbox_xadd_success_total", outboxXaddSuccessTotal.get());
        m.put("outbox_xadd_failure_total", outboxXaddFailureTotal.get());
        m.put("kafka_publish_success_total", kafkaPublishSuccessTotal.get());
        m.put("kafka_publish_failure_total", kafkaPublishFailureTotal.get());
        m.put("kafka_publish_latency_ms_last", kafkaPublishLatencyMsLast.get());
        m.put("kafka_publish_latency_ms_total", kafkaPublishLatencyMsTotal.get());
        m.put("kafka_publish_count_total", kafkaPublishCountTotal.get());
        m.put("pending_reclaimed_total", pendingReclaimedTotal.get());
        m.put("outbox_lag_seconds_last", outboxLagSecondsLast.get());
        m.put("outbox_pending_total", outboxPendingTotal.get());
        m.put("outbox_pending_oldest_idle_ms", outboxPendingOldestIdleMs.get());
        return m;
    }
}
