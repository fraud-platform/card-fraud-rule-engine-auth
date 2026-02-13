package com.fraud.engine.integration;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.*;

@QuarkusTest
class HealthIntegrationTest {

    @Test
    void testHealthEndpoint_ReturnsOk() {
        given()
        .when()
            .get("/v1/evaluate/health")
        .then()
            .statusCode(200)
            .body("status", equalTo("UP"));
    }

    @Test
    void testHealthEndpoint_HasStorageAccessible() {
        given()
        .when()
            .get("/v1/evaluate/health")
        .then()
            .statusCode(200)
            .body("storageAccessible", notNullValue());
    }

    @Test
    void testLivenessEndpoint() {
        given()
        .when()
            .get("/health/live")
        .then()
            .statusCode(200);
    }

    @Test
    void testReadinessEndpoint() {
        given()
        .when()
            .get("/health/ready")
        .then()
            .statusCode(200);
    }
}
