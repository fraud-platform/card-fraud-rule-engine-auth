package com.fraud.engine.outbox;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.engine.RuleEvaluator;
import com.fraud.engine.util.EngineMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Async durability dispatcher for AUTH.
 *
 * <p>Request thread does an in-memory enqueue only; background thread persists to the configured outbox.
 * If the queue is full, the event is dropped and AUTH response is never blocked.
 */
@ApplicationScoped
public class AsyncOutboxDispatcher {

    private static final Logger LOG = Logger.getLogger(AsyncOutboxDispatcher.class);
    private static final int MAX_DRAIN_BURST = 64;

    @ConfigProperty(name = "app.auth.async-durability.enabled", defaultValue = "true")
    boolean enabled;

    @ConfigProperty(name = "app.auth.async-durability.queue-capacity", defaultValue = "10000")
    int queueCapacity;

    @ConfigProperty(name = "app.auth.async-durability.poll-interval-ms", defaultValue = "5")
    int pollIntervalMs;

    @Inject
    OutboxFacade outboxClient;

    @Inject
    EngineMetrics engineMetrics;

    private BlockingQueue<OutboxEvent> queue;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(
            r -> {
                Thread t = new Thread(r, "auth-async-durability-writer-" + UUID.randomUUID());
                t.setDaemon(true);
                return t;
            });

    private volatile boolean running;
    private volatile OutboxEvent pending;

    @PostConstruct
    void start() {
        queue = new ArrayBlockingQueue<>(Math.max(1, queueCapacity));
        engineMetrics.setAuthAsyncQueueDepth(0);
        if (!enabled) {
            LOG.info("AUTH async durability is DISABLED (no outbox persistence for AUTH)");
            return;
        }
        running = true;
        worker.submit(this::runLoop);
        LOG.infof("AUTH async durability enabled (queueCapacity=%d, idleWaitMs=%d)",
                queueCapacity, Math.max(1, pollIntervalMs));
    }

    @PreDestroy
    void stop() {
        running = false;
        worker.shutdownNow();
    }

    /**
     * Enqueue AUTH event for async durability.
     * Returns true if queued, false if dropped/disabled.
     */
    public boolean enqueueAuth(TransactionContext tx, Decision authDecision) {
        if (!enabled) {
            engineMetrics.incrementAuthAsyncDurabilityDisabledDrops();
            engineMetrics.incrementAuthAsyncEnqueueDropped();
            return false;
        }
        if (tx == null || authDecision == null) {
            engineMetrics.incrementAuthAsyncDurabilityInvalidDrops();
            engineMetrics.incrementAuthAsyncEnqueueDropped();
            return false;
        }
        if (!RuleEvaluator.EVAL_AUTH.equalsIgnoreCase(authDecision.getEvaluationType())) {
            // Defensive: only intended for AUTH
            engineMetrics.incrementAuthAsyncDurabilityInvalidDrops();
            engineMetrics.incrementAuthAsyncEnqueueDropped();
            return false;
        }

        boolean offered = queue.offer(new OutboxEvent(tx, authDecision));
        if (offered) {
            engineMetrics.incrementAuthAsyncDurabilityEnqueued();
            engineMetrics.incrementAuthAsyncEnqueueOk();
        } else {
            engineMetrics.incrementAuthAsyncDurabilityQueueFullDrops();
            engineMetrics.incrementAuthAsyncEnqueueDropped();
        }
        engineMetrics.setAuthAsyncQueueDepth(queue.size());
        return offered;
    }

    private void runLoop() {
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                drainLoopIteration();
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                LOG.warnf(e, "AUTH async durability drain iteration failed");
                sleepBackoff();
            }
        }
    }

    private void drainLoopIteration() throws InterruptedException {
        OutboxEvent current = pending;
        if (current == null) {
            current = queue.poll(Math.max(1, pollIntervalMs), TimeUnit.MILLISECONDS);
            if (current == null) {
                engineMetrics.setAuthAsyncQueueDepth(queue.size());
                return;
            }
        }

        if (!persist(current)) {
            pending = current;
            sleepBackoff();
            return;
        }

        pending = null;
        drainBurst();
        engineMetrics.setAuthAsyncQueueDepth(queue.size());
    }

    private void drainBurst() {
        for (int i = 0; i < MAX_DRAIN_BURST; i++) {
            OutboxEvent next = queue.poll();
            if (next == null) {
                return;
            }
            if (!persist(next)) {
                pending = next;
                return;
            }
        }
    }

    private boolean persist(OutboxEvent event) {
        try {
            outboxClient.append(event);
            engineMetrics.incrementAuthAsyncDurabilityPersisted();
            return true;
        } catch (Exception e) {
            engineMetrics.incrementAuthAsyncDurabilityPersistFailures();
            // Keep pending and retry later; do not block request threads.
            LOG.debugf(e, "AUTH async durability persist failed (will retry)");
            return false;
        }
    }

    private void sleepBackoff() {
        try {
            TimeUnit.MILLISECONDS.sleep(Math.max(1, pollIntervalMs));
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }
}
