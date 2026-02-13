package com.fraud.engine.engine;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.testing.TransactionDataGenerator;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.http.ContentType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Negative / Security Tests")
class SecurityInputValidationTest {

    private TransactionContext basicTransaction;
    private Ruleset ruleset;

    @BeforeEach
    void setUp() {
        basicTransaction = TransactionDataGenerator.customTransaction(
            new BigDecimal("100.00"),
            "USD",
            "US",
            "merch_123"
        );

        ruleset = new Ruleset("SECURITY_TEST", 1);
        ruleset.setRules(new ArrayList<>());
    }

    @Nested
    @DisplayName("SQL Injection Prevention")
    class SqlInjectionTests {

        @Test
        @DisplayName("SQL injection strings in merchant_name should be handled safely")
        void testSqlInjectionInMerchantName() {
            String[] sqlInjections = {
                "'; DROP TABLE users;--",
                "' OR '1'='1",
                "admin'--",
                "UNION SELECT * FROM users",
                "1; DELETE FROM transactions WHERE 1=1"
            };

            for (String injection : sqlInjections) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setMerchantName(injection);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision(),
                    "Should handle SQL injection string safely: " + injection);
            }
        }

        @Test
        @DisplayName("SQL injection strings in card_hash should be handled safely")
        void testSqlInjectionInCardHash() {
            String[] sqlInjections = {
                "'; DROP TABLE cards;--",
                "' OR '1'='1",
                "admin'--"
            };

            for (String injection : sqlInjections) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setCardHash("hash_" + injection);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }

        @Test
        @DisplayName("SQL injection strings in email should be handled safely")
        void testSqlInjectionInEmail() {
            String[] sqlInjections = {
                "'; DROP TABLE users;--",
                "' OR '1'='1'--"
            };

            for (String injection : sqlInjections) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setEmail("test" + injection + "@example.com");

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }
    }

    @Nested
    @DisplayName("XSS Prevention")
    class XssTests {

        @Test
        @DisplayName("XSS payloads in string fields should be handled safely")
        void testXssInStringFields() {
            String[] xssPayloads = {
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "<svg onload=alert(1)>",
                "{{constructor.constructor('alert(1)')()}}",
                "<iframe src='javascript:alert(1)'>"
            };

            for (String xss : xssPayloads) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setMerchantName(xss);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }

        @Test
        @DisplayName("XSS in device_id should be handled safely")
        void testXssInDeviceId() {
            String[] xssPayloads = {
                "<script>alert(1)</script>",
                "device_<img src=x onerror=alert(1)>"
            };

            for (String xss : xssPayloads) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setDeviceId(xss);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }
    }

    @Nested
    @DisplayName("Unicode Edge Cases")
    class UnicodeTests {

        @Test
        @DisplayName("Unicode characters in string fields should be handled")
        void testUnicodeInStringFields() {
            String[] unicodeStrings = {
                "München",                  // German umlaut
                "北京",                     // Chinese
                "Москва",                   // Russian Cyrillic
                "东京",                     // Japanese
                "Ελλάδα",                   // Greek
                "서울",                     // Korean
                "🚩 Transaction",           // Emoji
                "Hello" + (char)0 + "World",           // Null byte
                "" + (char)0 + (char)1 + (char)2        // Control characters
            };

            for (String unicode : unicodeStrings) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setMerchantName(unicode);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }

        @Test
        @DisplayName("Right-to-left override characters should be handled")
        void testRtlOverride() {
            String rtlString = "Hello\u202EWorld\u202C";

            TransactionContext txn = TransactionDataGenerator.customTransaction(
                new BigDecimal("50.00"), "USD", "US", "merch_test"
            );
            txn.setMerchantName(rtlString);

            RuleEvaluator evaluator = new RuleEvaluator();
            Decision decision = evaluator.evaluate(txn, ruleset);

            assertNotNull(decision);
            assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
        }
    }

    @Nested
    @DisplayName("Boundary String Lengths")
    class StringLengthTests {

        @Test
        @DisplayName("Very long strings should be handled without errors")
        void testVeryLongStrings() {
            char[] chars = new char[10000];
            java.util.Arrays.fill(chars, 'X');
            String longString = new String(chars);

            TransactionContext txn = TransactionDataGenerator.customTransaction(
                new BigDecimal("50.00"), "USD", "US", "merch_test"
            );
            txn.setMerchantName(longString);
            txn.setCardHash("hash_" + longString.substring(0, 100));
            txn.setDeviceId(longString.substring(0, 50));
            txn.setEmail(longString.substring(0, 50) + "@example.com");

            RuleEvaluator evaluator = new RuleEvaluator();
            Decision decision = evaluator.evaluate(txn, ruleset);

            assertNotNull(decision);
        }

        @Test
        @DisplayName("Empty strings should be handled")
        void testEmptyStrings() {
            TransactionContext txn = TransactionDataGenerator.customTransaction(
                new BigDecimal("50.00"), "USD", "US", "merch_test"
            );
            txn.setMerchantName("");
            txn.setCardHash("");
            txn.setDeviceId("");
            txn.setEmail("");

            RuleEvaluator evaluator = new RuleEvaluator();
            Decision decision = evaluator.evaluate(txn, ruleset);

            assertNotNull(decision);
            assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
        }
    }

    @Nested
    @DisplayName("Null Byte Injection")
    class NullByteTests {

        @Test
        @DisplayName("Null bytes in strings should be handled")
        void testNullBytes() {
            String[] nullByteStrings = {
                "test" + (char)0 + "value",
                "" + (char)0 + "start",
                "end" + (char)0,
                "mid" + (char)0 + "dle"
            };

            for (String nullStr : nullByteStrings) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setMerchantName(nullStr);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }
    }

    @Nested
    @DisplayName("Request Size Limits")
    class RequestSizeTests {

        @Test
        @DisplayName("Large custom fields should be handled")
        void testLargeCustomFields() {
            TransactionContext txn = TransactionDataGenerator.customTransaction(
                new BigDecimal("50.00"), "USD", "US", "merch_test"
            );

            Map<String, Object> largeFields = new HashMap<>();
            char[] chars = new char[5000];
            java.util.Arrays.fill(chars, 'A');
            largeFields.put("large_field", new String(chars));
            largeFields.put("many_fields_count", 100);
            txn.setCustomFields(largeFields);

            RuleEvaluator evaluator = new RuleEvaluator();
            Decision decision = evaluator.evaluate(txn, ruleset);

            assertNotNull(decision);
            assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
        }
    }

    @Nested
    @DisplayName("Malformed Input Handling")
    class MalformedInputTests {

        @Test
        @DisplayName("Special characters in transaction ID should be handled")
        void testSpecialCharsInTransactionId() {
            String[] specialIds = {
                "txn with spaces",
                "txn-with-dashes",
                "txn_with_underscores",
                "txn.with.dots",
                "txn/with/slashes",
                "txn\\with\\backsashes",
                "txn:with:colons"
            };

            for (String id : specialIds) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setTransactionId(id);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
            }
        }

        @Test
        @DisplayName("IPv6 addresses should be handled")
        void testIpv6Addresses() {
            String[] ipv6Addresses = {
                "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
                "::1",
                "2001:db8::1"
            };

            for (String ip : ipv6Addresses) {
                TransactionContext txn = TransactionDataGenerator.customTransaction(
                    new BigDecimal("50.00"), "USD", "US", "merch_test"
                );
                txn.setIpAddress(ip);

                RuleEvaluator evaluator = new RuleEvaluator();
                Decision decision = evaluator.evaluate(txn, ruleset);

                assertNotNull(decision);
                assertEquals(Decision.DECISION_APPROVE, decision.getDecision());
            }
        }
    }
}
