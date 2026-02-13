package com.fraud.engine.startup;

import com.fraud.engine.dto.FieldRegistryManifest;
import com.fraud.engine.loader.FieldRegistryLoader;
import com.fraud.engine.ruleset.RulesetLoader;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Validates S3 availability at startup.
 * <p>
 * <b>Design Decision DD-001 (Revised):</b>
 * <ul>
 *   <li>BOTH field registry AND ruleset must be available from S3</li>
 *   <li>Fail-fast if EITHER is missing</li>
 *   <li>Hot-reload failures are non-fatal (continue with previous version)</li>
 *   <li>Version compatibility checked during hot-reload</li>
 * </ul>
 *
 * <p><b>Startup Behavior:</b>
 *
 * | Scenario | Behavior |
 * |----------|----------|
 * | Both available | ✅ Normal startup |
 * | Field registry only | ❌ Fail startup - ruleset required |
 * | Ruleset only | ❌ Fail startup - field registry required |
 * | Both unavailable | ❌ Fail startup - both required |
 *
 * <p><b>Hot-Reload Behavior:</b>
 *
 * | Scenario | Behavior |
 * |----------|----------|
 * | Versions compatible | ✅ Hot reload both |
 * | Versions mismatch | ⚠️ Continue with current, alert |
 * | S3 error | ⚠️ Continue with current, alert |
 */
@ApplicationScoped
public class S3StartupValidator {

    private static final Logger LOG = Logger.getLogger(S3StartupValidator.class);

    @ConfigProperty(name = "app.startup.validation.enabled", defaultValue = "true")
    boolean validationEnabled;

    @ConfigProperty(name = "app.ruleset.required-keys", defaultValue = "CARD_AUTH,CARD_MONITORING")
    String requiredRulesetKeys;

    @Inject
    FieldRegistryLoader fieldRegistryLoader;

    @Inject
    RulesetLoader rulesetLoader;

    private volatile boolean fieldRegistryAvailable = false;
    private volatile boolean rulesetAvailable = false;

    @PostConstruct
    void validate() {
        if (!validationEnabled) {
            LOG.warn("Startup validation is DISABLED. Engine may start with incomplete configuration.");
            return;
        }

        LOG.info("Validating S3 artifacts at startup...");

        // Check field registry availability
        FieldRegistryManifest manifest = fieldRegistryLoader.loadManifest();
        fieldRegistryAvailable = (manifest != null);

        // Check ruleset manifest availability
        rulesetAvailable = checkRulesetManifests();

        LOG.infof("S3 Availability Check: FieldRegistry=%s, Ruleset=%s",
                fieldRegistryAvailable ? "✓ AVAILABLE" : "✗ UNAVAILABLE",
                rulesetAvailable ? "✓ AVAILABLE" : "✗ UNAVAILABLE");

        // Fail-fast if EITHER is unavailable
        if (!fieldRegistryAvailable) {
            String errorMsg = String.format(
                    "CRITICAL STARTUP FAILURE: Field registry is unavailable from S3.%n" +
                    "  Required: fields/registry/manifest.json%n" +
                    "  Engine CANNOT start without field registry.%n" +
                    "  Please verify:%n" +
                    "    1. S3/MinIO is running and accessible%n" +
                    "    2. Bucket exists and is accessible%n" +
                    "    3. Field registry artifacts have been published by rule-management service"
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
                    "    2. Bucket exists and is accessible%n" +
                    "    3. Ruleset artifacts and manifest.json have been published by rule-management service"
            );
            LOG.error(errorMsg);
            throw new IllegalStateException("Startup validation failed: Rulesets unavailable from S3");
        }

        LOG.info("✓ Startup validation complete: Both field registry and rulesets available");
        LOG.infof("  Field Registry Version: %d", manifest.getRegistryVersion());
    }

    /**
     * Returns whether field registry was available at startup.
     *
     * @return true if available from S3, false otherwise
     */
    public boolean isFieldRegistryAvailable() {
        return fieldRegistryAvailable;
    }

    /**
     * Returns whether ruleset was available at startup.
     *
     * @return true if available from S3, false otherwise
     */
    public boolean isRulesetAvailable() {
        return rulesetAvailable;
    }

    /**
     * Returns whether all required artifacts were available at startup.
     *
     * @return true if both available, false if any missing
     */
    public boolean isStartupHealthy() {
        return fieldRegistryAvailable && rulesetAvailable;
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
}
