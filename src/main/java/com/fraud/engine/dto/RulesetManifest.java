package com.fraud.engine.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * DTO representing the ruleset manifest stored in S3.
 * The manifest is the runtime source-of-truth pointer for the latest version.
 */
public class RulesetManifest {

    @JsonProperty("schema_version")
    private String schemaVersion;

    @JsonProperty("environment")
    private String environment;

    @JsonProperty("region")
    private String region;

    @JsonProperty("country")
    private String country;

    @JsonProperty("ruleset_key")
    private String rulesetKey;

    @JsonProperty("ruleset_version")
    private Integer rulesetVersion;

    @JsonProperty("field_registry_version")
    private Integer fieldRegistryVersion;

    @JsonProperty("artifact_uri")
    private String artifactUri;

    @JsonProperty("checksum")
    private String checksum;

    @JsonProperty("published_at")
    private Instant publishedAt;

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public String getEnvironment() {
        return environment;
    }

    public String getRegion() {
        return region;
    }

    public String getCountry() {
        return country;
    }

    public String getRulesetKey() {
        return rulesetKey;
    }

    public Integer getRulesetVersion() {
        return rulesetVersion;
    }

    public Integer getFieldRegistryVersion() {
        return fieldRegistryVersion;
    }

    public String getArtifactUri() {
        return artifactUri;
    }

    public String getChecksum() {
        return checksum;
    }

    public Instant getPublishedAt() {
        return publishedAt;
    }
}
