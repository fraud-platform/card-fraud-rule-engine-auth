package com.fraud.engine.util;

import org.jboss.logging.Logger;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility for sending structured alerts to monitoring systems.
 * <p>
 * Provides consistent alert logging with structured metadata that can be
 * detected by log aggregators (Datadog, Splunk, Loki, etc.).
 */
public final class AlertLogger {

    private AlertLogger() {}

    private static final Logger LOG = Logger.getLogger(AlertLogger.class);

    public static void hotReloadFailed(String component, int attemptedVersion, int currentVersion, String error) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("alert_type", "HOT_RELOAD_FAILURE");
        alertData.put("severity", "WARNING");
        alertData.put("component", component);
        alertData.put("attempted_version", attemptedVersion);
        alertData.put("current_version", currentVersion);
        alertData.put("error", error);

        LOG.warnf("ALERT: Hot-reload failed for %s v%d. Current: v%d. Error: %s",
                component, attemptedVersion, currentVersion, error);
        LOG.debugf("Alert details: %s", alertData);
    }

    public static void versionMismatch(String component, int fieldRegistryVersion, int rulesetMinVersion) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("alert_type", "VERSION_MISMATCH");
        alertData.put("severity", "WARNING");
        alertData.put("component", component);
        alertData.put("field_registry_version", fieldRegistryVersion);
        alertData.put("ruleset_min_version", rulesetMinVersion);

        LOG.warnf("ALERT: Version mismatch for %s. Field registry v%d requires ruleset v%d+",
                component, fieldRegistryVersion, rulesetMinVersion);
        LOG.debugf("Alert details: %s", alertData);
    }

    public static void checksumValidationFailed(String component, int version) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("alert_type", "CHECKSUM_VALIDATION_FAILED");
        alertData.put("severity", "CRITICAL");
        alertData.put("component", component);
        alertData.put("version", version);

        LOG.errorf("ALERT: Checksum validation failed for %s v%d. Artifact may be tampered.",
                component, version);
        LOG.debugf("Alert details: %s", alertData);
    }

    public static void storageAccessFailed(String component, String storageType, String error) {
        Map<String, Object> alertData = new HashMap<>();
        alertData.put("alert_type", "STORAGE_ACCESS_FAILURE");
        alertData.put("severity", "WARNING");
        alertData.put("component", component);
        alertData.put("storage_type", storageType);
        alertData.put("error", error);

        LOG.warnf("ALERT: %s storage access failed: %s. Error: %s",
                storageType, component, error);
        LOG.debugf("Alert details: %s", alertData);
    }
}
