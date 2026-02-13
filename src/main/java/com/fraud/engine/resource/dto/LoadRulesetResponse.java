package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Load ruleset response.
 */
@Schema(description = "Load ruleset response")
public class LoadRulesetResponse {

    @Schema(description = "Whether loading succeeded")
    public boolean success;

    @Schema(description = "Status message")
    public String message;

    @Schema(description = "Ruleset key")
    public String rulesetKey;

    @Schema(description = "Ruleset version")
    public int version;

    @Schema(description = "Country code")
    public String country;

    public LoadRulesetResponse(boolean success, String message, String rulesetKey,
                               int version, String country) {
        this.success = success;
        this.message = message;
        this.rulesetKey = rulesetKey;
        this.version = version;
        this.country = country;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public void setRulesetKey(String rulesetKey) {
        this.rulesetKey = rulesetKey;
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
