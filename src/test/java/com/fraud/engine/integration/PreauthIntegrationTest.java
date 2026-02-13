package com.fraud.engine.integration;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Integration tests for PREAUTH evaluation.
 */
@QuarkusTest
class PreauthIntegrationTest {

    private TransactionContext createTransaction(String txnId, String cardHash, double amount, String countryCode) {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId(txnId);
        txn.setCardHash(cardHash);
        txn.setAmount(BigDecimal.valueOf(amount));
        if (countryCode != null) {
            txn.setCountryCode(countryCode);
        }
        return txn;
    }

    @Test
    void testAuthBasicEvaluation() {
        TransactionContext txn = createTransaction("txn-test-001", "card-123", 50.00, "US");

        given()
            .contentType(ContentType.JSON)
            .body(txn)
        .when()
            .post("/v1/evaluate/auth")
        .then()
            .statusCode(200)
            .body("transaction_id", equalTo("txn-test-001"))
            .body("decision", notNullValue())
            .body("engine_mode", notNullValue());
    }

    @Test
    void testAuthHasTransactionId() {
        TransactionContext txn = createTransaction("txn-test-id", "card-id", 50.00, null);

        given()
            .contentType(ContentType.JSON)
            .body(txn)
        .when()
            .post("/v1/evaluate/auth")
        .then()
            .statusCode(200)
            .body("transaction_id", equalTo("txn-test-id"));
    }

    @Test
    void testAuthHasEngineMode() {
        TransactionContext txn = createTransaction("txn-test-time", "card-time", 50.00, null);

        given()
            .contentType(ContentType.JSON)
            .body(txn)
        .when()
            .post("/v1/evaluate/auth")
        .then()
            .statusCode(200)
            .body("engine_mode", notNullValue());
    }

    @Test
    void testAuthReturnsDecision() {
        TransactionContext txn = createTransaction("txn-test-latency", "card-latency", 50.00, null);

        given()
            .contentType(ContentType.JSON)
            .body(txn)
        .when()
            .post("/v1/evaluate/auth")
        .then()
            .statusCode(200)
            .body("decision", notNullValue());
    }

    @Test
    void testAuthWithUnknownRulesetType_ExpectFailOpen() {
        TransactionContext txn = createTransaction("txn-test-missing", "card-missing", 999.00, null);
        txn.setTransactionType("UNKNOWN_RULESET");

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

    /**
     * Simple DTO for test transaction creation.
     */
    public static class TransactionContext {
        @JsonProperty("transaction_id")
        private String transactionId;
        @JsonProperty("card_hash")
        private String cardHash;
        private BigDecimal amount;
        @JsonProperty("country_code")
        private String countryCode;
        @JsonProperty("transaction_type")
        private String transactionType;

        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }

        public String getCardHash() { return cardHash; }
        public void setCardHash(String cardHash) { this.cardHash = cardHash; }

        public BigDecimal getAmount() { return amount; }
        public void setAmount(BigDecimal amount) { this.amount = amount; }

        public String getCountryCode() { return countryCode; }
        public void setCountryCode(String countryCode) { this.countryCode = countryCode; }

        public String getTransactionType() { return transactionType; }
        public void setTransactionType(String transactionType) { this.transactionType = transactionType; }
    }
}
