package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.Map;

/**
 * Metrics response.
 */
@Schema(description = "Metrics response")
public class MetricsResponse {

    @Schema(description = "Ruleset cache size")
    public int rulesetCacheSize;

    @Schema(description = "Storage accessible")
    public boolean storageAccessible;

    @Schema(description = "JVM uptime in ms")
    public long jvmUptime;

    @Schema(description = "JVM used memory in bytes")
    public long jvmMemory;

    // ========== Field Registry Metrics ==========

    @Schema(description = "Field registry version")
    public int fieldRegistryVersion;

    @Schema(description = "Field registry source (s3 or builtin)")
    public String fieldRegistrySource;

    @Schema(description = "Number of fields in registry")
    public int fieldCount;

    @Schema(description = "Whether field registry watcher is running")
    public boolean fieldRegistryWatcherRunning;

    // ========== S3 Availability (Fail-Fast Startup) ==========

    @Schema(description = "Whether field registry was available from S3 at startup")
    public boolean fieldRegistryS3Available;

    @Schema(description = "Whether ruleset was available from S3 at startup")
    public boolean rulesetS3Available;

    @Schema(description = "Whether all required artifacts were available at startup")
    public boolean startupHealthy;

    // ========== Engine Counters ==========

    @Schema(description = "Engine observability counters")
    public Map<String, Long> engineCounters;

    public Map<String, Long> getEngineCounters() {
        return engineCounters;
    }

    public void setEngineCounters(Map<String, Long> engineCounters) {
        this.engineCounters = engineCounters;
    }

    public int getRulesetCacheSize() {
        return rulesetCacheSize;
    }

    public void setRulesetCacheSize(int rulesetCacheSize) {
        this.rulesetCacheSize = rulesetCacheSize;
    }

    public boolean isStorageAccessible() {
        return storageAccessible;
    }

    public void setStorageAccessible(boolean storageAccessible) {
        this.storageAccessible = storageAccessible;
    }

    public long getJvmUptime() {
        return jvmUptime;
    }

    public void setJvmUptime(long jvmUptime) {
        this.jvmUptime = jvmUptime;
    }

    public long getJvmMemory() {
        return jvmMemory;
    }

    public void setJvmMemory(long jvmMemory) {
        this.jvmMemory = jvmMemory;
    }

    public int getFieldRegistryVersion() {
        return fieldRegistryVersion;
    }

    public void setFieldRegistryVersion(int fieldRegistryVersion) {
        this.fieldRegistryVersion = fieldRegistryVersion;
    }

    public String getFieldRegistrySource() {
        return fieldRegistrySource;
    }

    public void setFieldRegistrySource(String fieldRegistrySource) {
        this.fieldRegistrySource = fieldRegistrySource;
    }

    public int getFieldCount() {
        return fieldCount;
    }

    public void setFieldCount(int fieldCount) {
        this.fieldCount = fieldCount;
    }

    public boolean isFieldRegistryWatcherRunning() {
        return fieldRegistryWatcherRunning;
    }

    public void setFieldRegistryWatcherRunning(boolean fieldRegistryWatcherRunning) {
        this.fieldRegistryWatcherRunning = fieldRegistryWatcherRunning;
    }

    public boolean isFieldRegistryS3Available() {
        return fieldRegistryS3Available;
    }

    public void setFieldRegistryS3Available(boolean fieldRegistryS3Available) {
        this.fieldRegistryS3Available = fieldRegistryS3Available;
    }

    public boolean isRulesetS3Available() {
        return rulesetS3Available;
    }

    public void setRulesetS3Available(boolean rulesetS3Available) {
        this.rulesetS3Available = rulesetS3Available;
    }

    public boolean isStartupHealthy() {
        return startupHealthy;
    }

    public void setStartupHealthy(boolean startupHealthy) {
        this.startupHealthy = startupHealthy;
    }
}
