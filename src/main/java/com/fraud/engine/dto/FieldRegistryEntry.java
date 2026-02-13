package com.fraud.engine.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

import java.util.List;

/**
 * DTO representing a single field definition in the field registry.
 * <p>
 * This maps to the field definitions that will be managed in rule-management
 * and published to S3 as part of fields.json.
 */
@Schema(description = "A single field definition in the field registry")
public class FieldRegistryEntry {

    @Schema(description = "Unique field identifier (integer ID)")
    public int fieldId;

    @Schema(description = "Field key name (e.g., 'amount', 'card_hash')")
    public String fieldKey;

    @Schema(description = "Human-readable display name")
    public String displayName;

    @Schema(description = "Field description")
    public String description;

    @Schema(description = "Data type (STRING, NUMBER, BOOLEAN, etc.)")
    public String dataType;

    @Schema(description = "List of operators allowed for this field")
    public List<String> allowedOperators;

    @Schema(description = "Whether multiple values are allowed")
    public boolean multiValueAllowed;

    @Schema(description = "Whether this field contains sensitive data (PII)")
    public boolean isSensitive;

    public FieldRegistryEntry() {
    }

    public FieldRegistryEntry(int fieldId, String fieldKey, String displayName,
                              String description, String dataType,
                              List<String> allowedOperators,
                              boolean multiValueAllowed, boolean isSensitive) {
        this.fieldId = fieldId;
        this.fieldKey = fieldKey;
        this.displayName = displayName;
        this.description = description;
        this.dataType = dataType;
        this.allowedOperators = allowedOperators;
        this.multiValueAllowed = multiValueAllowed;
        this.isSensitive = isSensitive;
    }

    // Getters and Setters

    public int getFieldId() {
        return fieldId;
    }

    public void setFieldId(int fieldId) {
        this.fieldId = fieldId;
    }

    public String getFieldKey() {
        return fieldKey;
    }

    public void setFieldKey(String fieldKey) {
        this.fieldKey = fieldKey;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDataType() {
        return dataType;
    }

    public void setDataType(String dataType) {
        this.dataType = dataType;
    }

    public List<String> getAllowedOperators() {
        return allowedOperators;
    }

    public void setAllowedOperators(List<String> allowedOperators) {
        this.allowedOperators = allowedOperators;
    }

    public boolean isMultiValueAllowed() {
        return multiValueAllowed;
    }

    public void setMultiValueAllowed(boolean multiValueAllowed) {
        this.multiValueAllowed = multiValueAllowed;
    }

    public boolean isSensitive() {
        return isSensitive;
    }

    public void setSensitive(boolean sensitive) {
        isSensitive = sensitive;
    }
}
