package com.fraud.engine.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

class AlertLoggerTest {

    @Test
    void hotReloadFailedDoesNotThrow() {
        assertDoesNotThrow(() ->
                AlertLogger.hotReloadFailed("FieldRegistry", 5, 4, "boom"));
    }

    @Test
    void versionMismatchDoesNotThrow() {
        assertDoesNotThrow(() ->
                AlertLogger.versionMismatch("Ruleset", 5, 4));
    }

    @Test
    void checksumValidationFailedDoesNotThrow() {
        assertDoesNotThrow(() ->
                AlertLogger.checksumValidationFailed("Ruleset", 8));
    }

    @Test
    void storageAccessFailedDoesNotThrow() {
        assertDoesNotThrow(() ->
                AlertLogger.storageAccessFailed("Ruleset", "S3", "timeout"));
    }
}
