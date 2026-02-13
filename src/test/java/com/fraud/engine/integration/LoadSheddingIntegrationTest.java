package com.fraud.engine.integration;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.equalTo;

/**
 * Integration tests for load shedding behavior.
 *
 * <p>LoadSheddingFilter runs at {@code Priorities.AUTHENTICATION - 100},
 * which is BEFORE the authentication filter. This means it can intercept
 * requests before auth checks.</p>
 *
 * <p>These tests use a test profile with {@code max-concurrent=0} to force
 * immediate load shedding.</p>
 */
@QuarkusTest
@TestProfile(LoadSheddingIntegrationTest.LoadSheddingProfile.class)
class LoadSheddingIntegrationTest {

    @Test
    void testMONITORINGLoadSheddingPreservesDecision() {
        Map<String, Object> payload = Map.of(
                "transaction_id", "txn-load-shed-1",
                "transaction_type", "PURCHASE",
                "decision", "DECLINE",
                "amount", 123.45,
                "currency", "USD"
        );

        given()
            .contentType(ContentType.JSON)
            .body(payload)
        .when()
            .post("/v1/evaluate/monitoring")
        .then()
            .statusCode(200)
            .header("X-Load-Shed", "true")
            .body("evaluation_type", equalTo("MONITORING"))
            .body("transaction_id", equalTo("txn-load-shed-1"))
            .body("decision", equalTo("DECLINE"))
            .body("engine_mode", equalTo("DEGRADED"))
            .body("engine_error_code", equalTo("LOAD_SHEDDING"))
            .body("ruleset_key", equalTo("CARD_MONITORING"));
    }

    public static class LoadSheddingProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "app.load-shedding.enabled", "true",
                    "app.load-shedding.max-concurrent", "0"
            );
        }
    }
}
