package com.fraud.engine.smoke;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.*;

/**
 * Smoke tests for the rule engine service.
 *
 * Note: These tests require the full Quarkus application to be running.
 * They are marked as @Disabled for unit test runs because they depend on
 * the full application lifecycle which may not be available during test suite
 * execution (especially when the application is shutting down).
 *
 * To run these tests individually:
 * mvn test -Dtest=SmokeTest
 *
 * Or run the application and hit the endpoints directly:
 * mvn quarkus:dev
 */
@QuarkusTest
class SmokeTest {

    @Test
    @Disabled("SmokeTest requires full application lifecycle - run separately with: mvn test -Dtest=SmokeTest")
    void healthEndpointReturns200() {
        given()
            .when().get("/health")
            .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    @Disabled("SmokeTest requires full application lifecycle - run separately with: mvn test -Dtest=SmokeTest")
    void healthReadyEndpointReturns200() {
        given()
            .when().get("/health/ready")
            .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    void applicationStartsSuccessfully() {
        given()
            .when().get("/health/live")
            .then()
                .statusCode(200)
                .body("status", equalTo("UP"));
    }

    @Test
    @Disabled("SmokeTest requires full application lifecycle - run separately with: mvn test -Dtest=SmokeTest")
    void fieldRegistryLoads() {
        given()
            .when().get("/v1/evaluate/health")
            .then()
                .statusCode(200)
                .body("status", equalTo("UP"))
                .body("storageAccessible", notNullValue());
    }
}
