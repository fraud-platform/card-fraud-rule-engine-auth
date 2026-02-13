package com.fraud.engine.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.time.Instant;
import java.util.List;

/**
 * DTO representing the complete field registry artifact.
 * <p>
 * This contains the actual field definitions loaded from S3.
 * Stored at: fields/registry/v{version}/fields.json
 */
@Schema(description = "Complete field registry artifact with all field definitions")
public class FieldRegistryArtifact {

    @Schema(description = "Schema version for compatibility checking")
    public int schemaVersion;

    @Schema(description = "Field registry version")
    public int registryVersion;

    @Schema(description = "List of field definitions")
    public List<FieldRegistryEntry> fields;

    @Schema(description = "Checksum of all field definitions")
    public String checksum;

    @Schema(description = "Timestamp when this version was created")
    public Instant createdAt;

    @Schema(description = "User or system that created this version")
    public String createdBy;

    public FieldRegistryArtifact() {
    }

    public FieldRegistryArtifact(int schemaVersion, int registryVersion,
                                 List<FieldRegistryEntry> fields,
                                 String checksum, Instant createdAt, String createdBy) {
        this.schemaVersion = schemaVersion;
        this.registryVersion = registryVersion;
        this.fields = fields;
        this.checksum = checksum;
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

    public List<FieldRegistryEntry> getFields() {
        return fields;
    }

    public void setFields(List<FieldRegistryEntry> fields) {
        this.fields = fields;
    }

    public String getChecksum() {
        return checksum;
    }

    public void setChecksum(String checksum) {
        this.checksum = checksum;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }
}
