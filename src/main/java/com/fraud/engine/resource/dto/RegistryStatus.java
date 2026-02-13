package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Registry status response.
 */
@Schema(description = "Registry status")
public class RegistryStatus {

    @Schema(description = "Total number of rulesets cached")
    public int totalRulesets;

    @Schema(description = "Number of countries with rulesets")
    public int countries;

    @Schema(description = "Whether S3/MinIO storage is accessible")
    public boolean storageAccessible;

    public int getTotalRulesets() {
        return totalRulesets;
    }

    public void setTotalRulesets(int totalRulesets) {
        this.totalRulesets = totalRulesets;
    }

    public int getCountries() {
        return countries;
    }

    public void setCountries(int countries) {
        this.countries = countries;
    }

    public boolean isStorageAccessible() {
        return storageAccessible;
    }

    public void setStorageAccessible(boolean storageAccessible) {
        this.storageAccessible = storageAccessible;
    }
}
