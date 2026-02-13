package com.fraud.engine.watcher;

import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.service.FieldRegistryService;
import com.fraud.engine.util.AlertLogger;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Watches the S3 field registry manifest for changes and triggers hot-reload.
 * <p>
 * This background service polls the manifest.json file periodically and
 * triggers a registry reload when the version changes. The reload is
 * non-blocking - the current registry continues serving requests during
 * the swap.
 * <p>
 * Configuration:
 * <ul>
 *   <li>app.field-registry.enable-hot-reload: Enable/disable watcher (default: true)</li>
 *   <li>app.field-registry.poll-interval: Poll interval in seconds (default: 30)</li>
 * </ul>
 */
@ApplicationScoped
public class FieldRegistryWatcher {

    private static final Logger LOG = Logger.getLogger(FieldRegistryWatcher.class);

    @ConfigProperty(name = "app.field-registry.enable-hot-reload", defaultValue = "true")
    boolean hotReloadEnabled;

    @ConfigProperty(name = "app.field-registry.poll-interval-seconds", defaultValue = "30")
    int pollIntervalSeconds;

    private final FieldRegistryLoader loader;
    private final FieldRegistryService service;

    private ScheduledExecutorService scheduler;
    private volatile int lastVersion = -1;
    private volatile boolean running = false;

    @Inject
    public FieldRegistryWatcher(FieldRegistryLoader loader, FieldRegistryService service) {
        this.loader = loader;
        this.service = service;
    }

    @PostConstruct
    void start() {
        if (!hotReloadEnabled) {
            LOG.info("FieldRegistryWatcher is disabled via configuration");
            return;
        }

        LOG.infof("Starting FieldRegistryWatcher (poll interval: %ds)", pollIntervalSeconds);

        // Initialize with current version
        FieldRegistryManifest manifest = loader.loadManifest();
        if (manifest != null) {
            lastVersion = manifest.getRegistryVersion();
            LOG.infof("Initial field registry version: %d", lastVersion);
        }

        running = true;
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "field-registry-watcher");
            thread.setDaemon(true);
            return thread;
        });

        scheduler.scheduleAtFixedRate(this::checkForUpdates, 0, pollIntervalSeconds, TimeUnit.SECONDS);

        LOG.info("FieldRegistryWatcher started successfully");
    }

    @PreDestroy
    void stop() {
        if (!running) {
            return;
        }

        LOG.info("Stopping FieldRegistryWatcher...");
        running = false;

        if (scheduler != null) {
            scheduler.shutdown();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    scheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                scheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        LOG.info("FieldRegistryWatcher stopped");
    }

    /**
     * Checks for updates by polling the manifest file.
     * <p>
     * If the registry version has changed, triggers a reload of the field registry.
     */
    private void checkForUpdates() {
        if (!running) {
            return;
        }

        try {
            FieldRegistryManifest manifest = loader.loadManifest();

            if (manifest == null) {
                // Manifest not found - keep current version
                LOG.debug("Manifest not found, keeping current registry version");
                return;
            }

            int currentVersion = manifest.getRegistryVersion();

            // Check if version has changed
            if (currentVersion > lastVersion) {
                LOG.infof("Field registry update detected: %d -> %d", lastVersion, currentVersion);

                try {
                    // Trigger reload
                    service.reload();

                    // Update last version only after successful reload
                    int newVersion = service.getRegistryVersion();
                    lastVersion = newVersion;

                    LOG.infof("Field registry hot-reload completed: now at version %d", newVersion);

                } catch (Exception e) {
                    AlertLogger.hotReloadFailed("FieldRegistry", currentVersion, lastVersion, e.getMessage());
                }
            } else if (currentVersion < lastVersion) {
                AlertLogger.versionMismatch("FieldRegistry", lastVersion, currentVersion);
                lastVersion = currentVersion;
            }

        } catch (Exception e) {
            // Hot-reload check failures are non-fatal
            LOG.warnf("Hot-reload check failed: %s. Will retry on next poll.", e.getMessage());
        }
    }

    /**
     * Manually triggers a check for updates.
     * <p>
     * Can be called via REST endpoint for admin-triggered reloads.
     */
    public void triggerCheck() {
        LOG.debug("Manual trigger of field registry update check");
        checkForUpdates();
    }

    /**
     * Returns whether the watcher is currently running.
     *
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Returns the last known registry version.
     *
     * @return the last version
     */
    public int getLastVersion() {
        return lastVersion;
    }
}
