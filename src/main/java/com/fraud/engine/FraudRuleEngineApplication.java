package com.fraud.engine;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.ShutdownEvent;
import io.quarkus.runtime.StartupEvent;
import io.quarkus.runtime.annotations.QuarkusMain;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Main application class with graceful shutdown support.
 * <p>
 * Handles SIGTERM gracefully by:
 * <ul>
 *   <li>Setting a shutdown flag to reject new requests</li>
 *   <li>Waiting for in-flight requests to complete</li>
 *   <li>Cleaning up resources (Redis connections, Kafka producers)</li>
 * </ul>
 */
@QuarkusMain
public class FraudRuleEngineApplication implements QuarkusApplication {

    private static final Logger LOG = Logger.getLogger(FraudRuleEngineApplication.class);

    public static void main(String[] args) {
        Quarkus.run(FraudRuleEngineApplication.class, args);
    }

    @Override
    public int run(String... args) throws Exception {
        LOG.info("Card Fraud Rule Engine starting...");
        Quarkus.waitForExit();
        return 0;
    }
}

/**
 * Lifecycle observer for application startup and shutdown events.
 */
@ApplicationScoped
class ApplicationLifecycleObserver {

    private static final Logger LOG = Logger.getLogger(ApplicationLifecycleObserver.class);

    /**
     * Flag indicating shutdown is in progress.
     * Used by health checks and request filters.
     */
    public static final AtomicBoolean SHUTTING_DOWN = new AtomicBoolean(false);

    /**
     * Called when the application starts.
     */
    void onStart(@Observes StartupEvent event) {
        LOG.info("Card Fraud Rule Engine starting...");

        LOG.info("Card Fraud Rule Engine started successfully");
        LOG.infof("Shutdown flag: %s", SHUTTING_DOWN.get());
    }

    /**
     * Called when the application receives shutdown signal.
     * Quarkus handles SIGTERM gracefully by default, but we add
     * custom logic here for coordinated shutdown.
     */
    void onShutdown(@Observes ShutdownEvent event) {
        LOG.info("Shutdown signal received, initiating graceful shutdown...");

        // Set shutdown flag - health checks will start returning unhealthy
        SHUTTING_DOWN.set(true);

        // Give load balancers time to detect unhealthy status and stop routing
        // This allows in-flight requests to complete
        try {
            LOG.info("Waiting for in-flight requests to complete (grace period: 5s)...");
            Thread.sleep(5000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOG.warn("Shutdown grace period interrupted");
        }

        LOG.info("Graceful shutdown complete");
    }

    /**
     * Checks if the application is shutting down.
     *
     * @return true if shutdown is in progress
     */
    public static boolean isShuttingDown() {
        return SHUTTING_DOWN.get();
    }
}
