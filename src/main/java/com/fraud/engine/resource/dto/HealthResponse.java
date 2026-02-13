package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Health check response.
 */
@Schema(description = "Health response")
public class HealthResponse {

    @Schema(example = "UP")
    public String status;

    @Schema(example = "true")
    public boolean storageAccessible;

    public HealthResponse(String status, boolean storageAccessible) {
        this.status = status;
        this.storageAccessible = storageAccessible;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public boolean isStorageAccessible() {
        return storageAccessible;
    }

    public void setStorageAccessible(boolean storageAccessible) {
        this.storageAccessible = storageAccessible;
    }
}
