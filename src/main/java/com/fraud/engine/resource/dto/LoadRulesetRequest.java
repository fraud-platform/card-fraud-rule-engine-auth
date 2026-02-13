package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Load ruleset request.
 */
@Schema(description = "Load ruleset request")
public class LoadRulesetRequest {

    @Schema(description = "Ruleset key", example = "CARD_AUTH")
    public String key;

    @Schema(description = "Ruleset version", example = "1")
    public int version;

    @Schema(description = "Country code (optional, defaults to global)", example = "US")
    public String country;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public int getVersion() {
        return version;
    }

    public void setVersion(int version) {
        this.version = version;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }
}
