package com.fraud.engine.startup;

import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.ruleset.RulesetRegistry;
import com.fraud.engine.util.EngineMetrics;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.List;

/**
 * Startup bean that pre-loads rulesets into the registry at application startup.
 * <p>
 * This ensures rulesets are available in memory before the application accepts
 * traffic, eliminating S3 I/O from the hot path and achieving 10-20ms latency.
 * <p>
 * <b>Fail-Fast Behavior:</b> If startup loading is enabled and any ruleset fails
 * to load, the application will fail to start. This prevents running with degraded
 * fraud detection capabilities.
 */
@ApplicationScoped
public class StartupRulesetLoader {

    private static final Logger LOG = Logger.getLogger(StartupRulesetLoader.class);

    @Inject
    RulesetRegistry rulesetRegistry;

    @Inject
    EngineMetrics engineMetrics;

    @ConfigProperty(name = "app.ruleset.startup.load-enabled", defaultValue = "true")
    boolean startupLoadEnabled;

    @ConfigProperty(name = "app.ruleset.startup.rulesets", defaultValue = "CARD_AUTH,CARD_MONITORING")
    List<String> startupRulesets;

    @ConfigProperty(name = "app.ruleset.startup.fail-fast", defaultValue = "true")
    boolean failFast;

    @ConfigProperty(name = "app.ruleset.startup.environment", defaultValue = "local")
    String environment;

    @ConfigProperty(name = "app.ruleset.startup.country", defaultValue = "US")
    String country;

    /**
     * Loads rulesets at application startup.
     * <p>
     * This method is called after the application has started but before
     * it accepts traffic. It loads the configured rulesets from S3/MinIO
     * into the in-memory registry.
     *
     * @param event the startup event
     */
    void onStart(@Observes StartupEvent event) {
        if (!startupLoadEnabled) {
            LOG.info("Startup ruleset loading is disabled");
            return;
        }

        LOG.info("Beginning startup ruleset loading...");
        long loadStart = System.currentTimeMillis();

        int successCount = 0;
        int failCount = 0;

        for (String rulesetKey : startupRulesets) {
            try {
                LOG.infof("Loading ruleset at startup: country=%s, key=%s", country, rulesetKey);

                // Load latest version via manifest with country-partitioned path support
                Ruleset compiled =
                        rulesetRegistry.getOrLoadLatest(country, rulesetKey);

                if (compiled == null) {
                    String error = String.format("Failed to load ruleset: %s (not found in S3/MinIO)", rulesetKey);
                    LOG.error(error);

                    engineMetrics.incrementStartupRulesetFailure();
                    if (failFast) {
                        throw new IllegalStateException("Startup ruleset loading failed: " + error);
                    }
                    failCount++;
                    continue;
                }

                successCount++;
                LOG.infof("Successfully loaded ruleset: %s v%d", rulesetKey, compiled.getVersion());

            } catch (Exception e) {
                LOG.errorf(e, "Error loading ruleset at startup: %s", rulesetKey);
                engineMetrics.incrementStartupRulesetFailure();

                if (failFast) {
                    throw new IllegalStateException("Startup ruleset loading failed for: " + rulesetKey, e);
                }
                failCount++;
            }
        }

        engineMetrics.recordStartupLoadTime(System.currentTimeMillis() - loadStart);

        if (successCount > 0) {
            LOG.infof("Startup ruleset loading complete: %d loaded, %d failed", successCount, failCount);
            LOG.infof("Total rulesets in registry: %d", rulesetRegistry.size());
        }

        if (failCount > 0 && failFast) {
            throw new IllegalStateException("Startup ruleset loading had failures");
        }
    }
}
