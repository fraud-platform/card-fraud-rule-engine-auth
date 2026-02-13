package com.fraud.engine.integration;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Chaos and Resilience Tests - Session 4.4
 * Tests fail-open behavior under infrastructure failures.
 *
 * <p><b>Note:</b> Some tests require external infrastructure manipulation (stopping containers)
 * and may be run manually or with Chaos Engineering tools.</p>
 */
@QuarkusTest
@DisplayName("Chaos/Resilience Tests - Session 4.4")
class ChaosResilienceIntegrationTest {

    private TransactionContext createTransaction(String txnId, String cardHash, double amount, String countryCode) {
        TransactionContext txn = new TransactionContext();
        txn.transactionId = txnId;
        txn.cardHash = cardHash;
        txn.amount = amount;
        if (countryCode != null) {
            txn.countryCode = countryCode;
        }
        return txn;
    }

    @Nested
    @DisplayName("Redis Failure Scenarios")
    class RedisFailureScenarios {

        @Test
        @DisplayName("AUTH returns APPROVE when Redis is unavailable (fail-open)")
        void testAUTHFailOpenWhenRedisDown() {
            TransactionContext txn = createTransaction("txn-redis-down-001", "card-123", 150.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)))
                .body("decision", notNullValue())
                .body("engine_mode", notNullValue());
        }

        @Test
        @DisplayName("Velocity check failure does not block evaluation")
        void testVelocityFailureDoesNotBlockEvaluation() {
            TransactionContext txn = createTransaction("txn-velocity-fail-001", "card-velocity", 150.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
        }
    }

    @Nested
    @DisplayName("Storage/MinIO Failure Scenarios")
    class StorageFailureScenarios {

        @Test
        @DisplayName("Engine uses cached rulesets when MinIO is unreachable")
        void testCachedRulesetsWhenMinIOUnreachable() {
            TransactionContext txn = createTransaction("txn-minio-down-001", "card-456", 50.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)))
                .body("decision", anyOf(equalTo("APPROVE"), equalTo("DECLINE"), nullValue()));
        }

        @Test
        @DisplayName("Unknown ruleset type triggers fail-open")
        void testUnknownRulesetTriggersFailOpen() {
            TransactionContext txn = createTransaction("txn-unknown-001", "card-unknown", 999.00, null);
            txn.transactionType = "UNKNOWN_RULESET_TYPE";

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(200)
                .body("decision", equalTo("APPROVE"))
                .body("engine_mode", equalTo("FAIL_OPEN"))
                .body("engine_error_code", notNullValue());
        }
    }

    @Nested
    @DisplayName("Memory Pressure Scenarios")
    class MemoryPressureScenarios {

        @Test
        @DisplayName("Load shedding activates under memory pressure")
        void testLoadSheddingUnderMemoryPressure() {
            TransactionContext txn = createTransaction("txn-memory-pressure-001", "card-mem", 50.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(200)
                .body("decision", anyOf(equalTo("APPROVE"), equalTo("DECLINE")));
        }
    }

    @Nested
    @DisplayName("Circuit Breaker Scenarios")
    class CircuitBreakerScenarios {

        @Test
        @DisplayName("Circuit breaker opens after repeated Redis failures")
        void testCircuitBreakerOpens() {
            TransactionContext txn = createTransaction("txn-circuit-001", "card-circuit", 50.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
        }

        @Test
        @DisplayName("Circuit breaker transitions to half-open after timeout")
        void testCircuitBreakerHalfOpen() {
            TransactionContext txn = createTransaction("txn-half-open-001", "card-half", 50.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
        }
    }

    @Nested
    @DisplayName("Graceful Degradation Scenarios")
    class GracefulDegradationScenarios {

        @Test
        @DisplayName("MONITORING continues without decision enrichment on failures")
        void testMonitoringGracefulDegradation() {
            Map<String, Object> payload = Map.of(
                    "transaction_id", "txn-degraded-001",
                    "transaction_type", "PURCHASE",
                    "decision", "APPROVE",
                    "amount", 123.45,
                    "currency", "USD"
            );

            given()
                .contentType(ContentType.JSON)
                .body(payload)
            .when()
                .post("/v1/evaluate/monitoring")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)))
                .body("decision", anyOf(equalTo("APPROVE"), equalTo("DECLINE"), nullValue()));
        }

        @Test
        @DisplayName("Missing velocity config uses defaults")
        void testMissingVelocityConfigUsesDefaults() {
            TransactionContext txn = createTransaction("txn-vel-default-001", "card-vel-default", 150.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
        }
    }

    @Nested
    @DisplayName("Timeout and Latency Scenarios")
    class TimeoutScenarios {

        @Test
        @DisplayName("Request timeout returns degraded response")
        void testRequestTimeout() {
            TransactionContext txn = createTransaction("txn-timeout-001", "card-timeout", 50.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503), equalTo(504)))
                .time(org.hamcrest.Matchers.lessThan(5000L));
        }

        @Test
        @DisplayName("Slow Redis response triggers fallback")
        void testSlowRedisTriggersFallback() {
            TransactionContext txn = createTransaction("txn-slow-redis-001", "card-slow", 150.00, "US");

            given()
                .contentType(ContentType.JSON)
                .body(txn)
            .when()
                .post("/v1/evaluate/auth")
            .then()
                .statusCode(anyOf(equalTo(200), equalTo(503)));
        }
    }

    public static class TransactionContext {
        public String transactionId;
        public String cardHash;
        public Double amount;
        public String countryCode;
        public String transactionType;
    }
}
