package com.fraud.engine.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * DTO representing the field registry manifest stored in S3.
 * <p>
 * The manifest contains metadata about the current field registry version
 * and points to the actual field definitions artifact.
 * <p>
 * Stored at: fields/registry/manifest.json
 */
@Schema(description = "Field registry manifest containing version and artifact location")
public class FieldRegistryManifest {

    @Schema(description = "Schema version for compatibility checking")
    public int schemaVersion;

    @Schema(description = "Current field registry version")
    public int registryVersion;

    @Schema(description = "S3 URI to the field definitions artifact")
    public String artifactUri;

    @Schema(description = "Checksum of the artifact (sha256:...)")
    public String checksum;

    @Schema(description = "Number of fields in this version")
    public int fieldCount;

    @Schema(description = "Timestamp when this version was created")
    public String createdAt;

    @Schema(description = "User or system that created this version")
    public String createdBy;

    public FieldRegistryManifest() {
    }

    public FieldRegistryManifest(int schemaVersion, int registryVersion, String artifactUri,
                                 String checksum, int fieldCount, String createdAt, String createdBy) {
        this.schemaVersion = schemaVersion;
        this.registryVersion = registryVersion;
        this.artifactUri = artifactUri;
        this.checksum = checksum;
        this.fieldCount = fieldCount;
        this.createdAt = createdAt;
        this.createdBy = createdBy;
    }

    // Getters and Setters

    public int getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(int schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public int getRegistryVersion() {
        return registryVersion;
    }

    public void setRegistryVersion(int registryVersion) {
        this.registryVersion = registryVersion;
    }

    public String getArtifactUri() {
        return artifactUri;
    }

    public void setArtifactUri(String artifactUri) {
        this.artifactUri = artifactUri;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public int getFieldCount() {
        return fieldCount;
    }

    public void setFieldCount(int fieldCount) {
        this.fieldCount = fieldCount;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }
}
