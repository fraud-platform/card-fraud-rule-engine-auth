package com.fraud.engine.resource.dto;

import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * Hot swap response.
 */
@Schema(description = "Hot swap response")
public class HotSwapResponse {

    @Schema(description = "Whether the swap succeeded")
    public boolean success;

    @Schema(description = "Status code")
    public String status;

    @Schema(description = "Status message")
    public String message;

    @Schema(description = "Previous version")
    public int oldVersion;

    @Schema(description = "New version")
    public int newVersion;

    public HotSwapResponse(boolean success, String status, String message,
                           int oldVersion, int newVersion) {
        this.success = success;
        this.status = status;
        this.message = message;
        this.oldVersion = oldVersion;
        this.newVersion = newVersion;
    }

    public boolean isSuccess() {
        return success;
    }

    public void setSuccess(boolean success) {
        this.success = success;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public int getOldVersion() {
        return oldVersion;
    }

    public void setOldVersion(int oldVersion) {
        this.oldVersion = oldVersion;
    }

    public int getNewVersion() {
        return newVersion;
    }

    public void setNewVersion(int newVersion) {
        this.newVersion = newVersion;
    }
}
