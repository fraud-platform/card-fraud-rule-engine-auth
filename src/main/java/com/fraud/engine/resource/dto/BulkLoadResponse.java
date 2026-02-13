package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Bulk load response.
 */
@Schema(description = "Bulk load response")
public class BulkLoadResponse {

    @Schema(description = "Number of rulesets successfully loaded")
    public int loaded;

    @Schema(description = "Total number of rulesets requested")
    public int total;

    public BulkLoadResponse(int loaded, int total) {
        this.loaded = loaded;
        this.total = total;
    }

    public int getLoaded() {
        return loaded;
    }

    public void setLoaded(int loaded) {
        this.loaded = loaded;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }
}
