package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Standard error response for API endpoints.
 * <p>
 * This is a shared class used by multiple resources to ensure
 * consistent error response format across the API.
 */
@Schema(description = "Error response")
public class ErrorResponse {

    @Schema(example = "ERROR_CODE")
    public String code;

    @Schema(example = "Error message")
    public String message;

    public ErrorResponse(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
