package com.fraud.engine.service;

import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.dto.RulesetManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.ruleset.RulesetLoader;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.util.AlertLogger;
import com.fraud.engine.util.EngineMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Coordinates hot-reload of field registry and rulesets with version compatibility checking.
 * <p>
 * Design Decision: Both field registry AND ruleset must be available at startup.
 * Hot-reload only happens if versions are compatible.
 * <p>
 * <b>Startup Behavior:</b>
 * <ul>
 *   <li>Both available → Normal startup</li>
 *   <li>Either missing → Fail startup (throw IllegalStateException)</li>
 * </ul>
 * <p>
 * <b>Hot-Reload Behavior:</b>
 * <ul>
 *   <li>Versions compatible → Reload both</li>
 *   <li>Versions mismatch → Continue with current versions, alert</li>
 *   <li>S3 error → Continue with current versions, alert</li>
 * </ul>
 */
@ApplicationScoped
public class HotReloadCoordinator {

    private static final Logger LOG = Logger.getLogger(HotReloadCoordinator.class);

    @ConfigProperty(name = "app.field-registry.enable-hot-reload", defaultValue = "true")
    boolean hotReloadEnabled;

    @ConfigProperty(name = "app.hot-reload.poll-interval-seconds", defaultValue = "30")
    int pollIntervalSeconds;

    @ConfigProperty(name = "app.ruleset.required-keys", defaultValue = "CARD_AUTH,CARD_MONITORING")
    String requiredRulesetKeys;

    @Inject
    FieldRegistryLoader fieldRegistryLoader;

    @Inject
    FieldRegistryService fieldRegistryService;

    @Inject
    RulesetLoader rulesetLoader;

    @Inject
    RulesetRegistry rulesetRegistry;

    @Inject
    EngineMetrics engineMetrics;

    private ScheduledExecutorService scheduler;
    private volatile int lastFieldRegistryVersion = -1;
    private volatile boolean running = false;

    @PostConstruct
    void start() {
        if (!hotReloadEnabled) {
            LOG.info("Hot reload is disabled via configuration");
            return;
        }

        LOG.infof("Starting HotReloadCoordinator (poll interval: %ds)", pollIntervalSeconds);

        // Validate startup - BOTH must be available
        validateStartup();

        // Initialize versions
        lastFieldRegistryVersion = fieldRegistryService.getRegistryVersion();

        running = true;
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "hot-reload-coordinator");
            thread.setDaemon(true);
            return thread;
        });

        scheduler.scheduleAtFixedRate(this::checkForUpdates, 0, pollIntervalSeconds, TimeUnit.SECONDS);

        LOG.info("HotReloadCoordinator started successfully");
    }

    /**
     * Validates that both field registry and at least one ruleset are available at startup.
     *
     * @throws IllegalStateException if either is unavailable
     */
    private void validateStartup() {
        LOG.info("Validating S3 artifacts for startup...");

        // Check field registry
        FieldRegistryManifest manifest = fieldRegistryLoader.loadManifest();
        boolean fieldRegistryAvailable = (manifest != null);

        // Check ruleset manifest availability
        boolean rulesetAvailable = checkRulesetManifests();

        if (!fieldRegistryAvailable) {
            String errorMsg = String.format(
                    "CRITICAL STARTUP FAILURE: Field registry is unavailable from S3.%n" +
                    "  Required: fields/registry/manifest.json%n" +
                    "  Engine CANNOT start without field registry.%n" +
                    "  Please verify:%n" +
                    "    1. S3/MinIO is running and accessible%n" +
                    "    2. Bucket exists: %s%n" +
                    "    3. Field registry artifacts have been published",
                    "fraud-gov-artifacts"
            );
            LOG.error(errorMsg);
            throw new IllegalStateException("Startup validation failed: Field registry unavailable from S3");
        }

        if (!rulesetAvailable) {
            String errorMsg = String.format(
                    "CRITICAL STARTUP FAILURE: Rulesets are unavailable from S3.%n" +
                    "  Required: rulesets/{ENV}/{RULESET_KEY}/manifest.json%n" +
                    "  Engine CANNOT start without required ruleset manifests.%n" +
                    "  Please verify:%n" +
                    "    1. S3/MinIO is running and accessible%n" +
                    "    2. Bucket exists: %s%n" +
                    "    3. Ruleset artifacts and manifest.json have been published",
                    "fraud-gov-artifacts"
            );
            LOG.error(errorMsg);
            throw new IllegalStateException("Startup validation failed: Rulesets unavailable from S3");
        }

        LOG.info("Startup validation complete: Both field registry and rulesets available");
    }

    /**
     * Checks for updates and performs coordinated hot-reload if versions are compatible.
     */
    private void checkForUpdates() {
        if (!running) {
            return;
        }

        try {
            // Check field registry
            FieldRegistryManifest manifest = fieldRegistryLoader.loadManifest();
            if (manifest == null) {
                LOG.warn("Hot-reload: Field registry manifest unavailable, continuing with current version");
                return;
            }

            int newFieldRegistryVersion = manifest.getRegistryVersion();

            // Check if field registry version changed
            if (newFieldRegistryVersion != lastFieldRegistryVersion) {
                LOG.infof("Hot-reload: Field registry version changed: %d -> %d",
                        lastFieldRegistryVersion, newFieldRegistryVersion);

                // Check if loaded rulesets are compatible with new field registry version
                boolean compatible = checkRulesetCompatibility(newFieldRegistryVersion);

                if (compatible) {
                    // Versions match - safe to reload both
                    performCoordinatedReload(newFieldRegistryVersion);
                    engineMetrics.incrementHotReloadSuccess();
                } else {
                    engineMetrics.incrementHotReloadFailure();
                    AlertLogger.versionMismatch("HotReloadCoordinator", newFieldRegistryVersion, lastFieldRegistryVersion);
                }
            }

        } catch (Exception e) {
            engineMetrics.incrementHotReloadFailure();
            AlertLogger.hotReloadFailed("HotReloadCoordinator", -1, lastFieldRegistryVersion, e.getMessage());
        }
    }

    /**
     * Checks if all currently loaded rulesets are compatible with the given field registry version.
     *
     * @param fieldRegistryVersion the field registry version to check
     * @return true if all rulesets are compatible, false otherwise
     */
    private boolean checkRulesetCompatibility(int fieldRegistryVersion) {
        return checkRulesetCompatibilityFromManifest(fieldRegistryVersion);
    }

    private boolean checkRulesetCompatibilityFromManifest(int fieldRegistryVersion) {
        boolean hasVersionInfo = false;

        for (String country : rulesetRegistry.getCountries()) {
            for (String key : rulesetRegistry.getRulesetKeys(country)) {
                RulesetManifest manifest = rulesetLoader.loadManifest(key);
                if (manifest == null) {
                    LOG.warnf("Compatibility check: Ruleset manifest missing for %s", key);
                    return false;
                }
                Integer rulesetRegistryVersion = manifest.getFieldRegistryVersion();
                if (rulesetRegistryVersion == null) {
                    LOG.warnf("Compatibility check skipped: manifest missing field_registry_version for %s", key);
                    continue;
                }
                hasVersionInfo = true;
                if (!rulesetRegistryVersion.equals(fieldRegistryVersion)) {
                    LOG.warnf("Compatibility check: Ruleset %s requires field registry version %d, but new version is %d",
                            key, rulesetRegistryVersion, fieldRegistryVersion);
                    return false;
                }
            }
        }

        if (!hasVersionInfo) {
            LOG.warn("Compatibility check skipped: no field_registry_version present in manifests");
        }
        return true;
    }

    private boolean checkRulesetManifests() {
        String[] keys = requiredRulesetKeys.split(",");
        boolean allAvailable = true;

        for (String rawKey : keys) {
            String key = rawKey.trim();
            if (key.isEmpty()) {
                continue;
            }
            boolean available = rulesetLoader.isManifestAvailable(key);
            if (!available) {
                allAvailable = false;
                LOG.errorf("Missing ruleset manifest: %s", key);
            }
        }

        return allAvailable;
    }

    /**
     * Performs coordinated hot-reload of both field registry and rulesets.
     *
     * @param newFieldRegistryVersion the new field registry version
     */
    private void performCoordinatedReload(int newFieldRegistryVersion) {
        try {
            LOG.info("Performing coordinated hot-reload...");

            // Reload field registry first
            fieldRegistryService.reload();
            int actualRegistryVersion = fieldRegistryService.getRegistryVersion();

            if (actualRegistryVersion != newFieldRegistryVersion) {
                LOG.warnf("Field registry reload resulted in version %d (expected %d)",
                        actualRegistryVersion, newFieldRegistryVersion);
                return;
            }

            // Reload all rulesets using hotSwap for each
            Set<String> reloadedKeys = new HashSet<>();
            for (String country : rulesetRegistry.getCountries()) {
                for (String key : rulesetRegistry.getRulesetKeys(country)) {
                    Ruleset current =
                            rulesetRegistry.getRuleset(country, key);
                    if (current != null) {
                        // Check if there's a newer version
                        Optional<Ruleset> latestOpt =
                                rulesetLoader.loadLatestCompiledRuleset(key);
                        if (latestOpt.isPresent()) {
                            Ruleset latest = latestOpt.get();
                            if (latest.getVersion() > current.getVersion()) {
                                // Check compatibility before swapping
                                Optional<Ruleset> rulesetOpt = rulesetLoader.loadCompiledRuleset(key, latest.getVersion());
                                if (rulesetOpt.isPresent()) {
                                    Ruleset ruleset = rulesetOpt.get();
                                    if (ruleset.isCompatibleWith(actualRegistryVersion)) {
                                        RulesetRegistry.HotSwapResult result =
                                                rulesetRegistry.hotSwap(country, key, latest.getVersion());
                                        if (result.success()) {
                                            reloadedKeys.add(key);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Update tracked version
            lastFieldRegistryVersion = actualRegistryVersion;

            LOG.infof("Coordinated hot-reload complete: Field registry v%d, Rulesets %s",
                    actualRegistryVersion, reloadedKeys);

        } catch (Exception e) {
            LOG.errorf(e, "Coordinated hot-reload failed");
            // Don't update tracked version - will retry
        }
    }

    /**
     * Manually triggers a check for updates.
     *
     * @return true if update was found and reloaded, false otherwise
     */
    public boolean triggerCheck() {
        int oldVersion = lastFieldRegistryVersion;
        checkForUpdates();
        return lastFieldRegistryVersion != oldVersion;
    }

    /**
     * Stops the coordinator.
     */
    @jakarta.annotation.PreDestroy
    void stop() {
        if (!running) {
            return;
        }

        LOG.info("Stopping HotReloadCoordinator...");
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

        LOG.info("HotReloadCoordinator stopped");
    }

    /**
     * Returns whether the coordinator is running.
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Returns the current field registry version.
     */
    public int getFieldRegistryVersion() {
        return lastFieldRegistryVersion;
    }
}
