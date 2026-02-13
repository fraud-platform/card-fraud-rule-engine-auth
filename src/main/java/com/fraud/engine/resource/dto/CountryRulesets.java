package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.Set;

/**
 * Country rulesets response.
 */
@Schema(description = "Country rulesets")
public class CountryRulesets {

    @Schema(description = "Country code")
    public String country;

    @Schema(description = "Ruleset keys")
    public Set<String> rulesetKeys;

    public CountryRulesets(String country, Set<String> rulesetKeys) {
        this.country = country;
        this.rulesetKeys = rulesetKeys;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public Set<String> getRulesetKeys() {
        return rulesetKeys;
    }

    public void setRulesetKeys(Set<String> rulesetKeys) {
        this.rulesetKeys = rulesetKeys;
    }
}
