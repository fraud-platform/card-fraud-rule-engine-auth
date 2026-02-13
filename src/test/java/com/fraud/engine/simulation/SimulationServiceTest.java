package com.fraud.engine.simulation;

import com.fraud.engine.domain.DebugInfo;
import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import io.quarkus.test.InjectMock;
import io.quarkus.test.Mock;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

/**
 * Tests for SimulationService.
 */
@QuarkusTest
class SimulationServiceTest {

    @Inject
    SimulationService simulationService;

    @BeforeEach
    void setUp() {
        // Reset any test state if needed
    }

    @Test
    void testSimulateSimpleDeclineRule() {
        String yaml = """
                key: TEST_SIMULATION
                evaluation_type: AUTH
                rules:
                  - id: high-amount
                    name: "High Amount Decline"
                    action: DECLINE
                    priority: 100
                    conditions:
                      - field: amount
                        operator: gt
                        value: 1000
                """;

        TransactionContext transaction = createTestTransaction(5000);
        SimulationService.SimulationResult result = simulationService.simulate(transaction, yaml);

        assertEquals("test-txn-5000", result.getTransactionId());
        assertEquals("DECLINE", result.getDecision());
        assertEquals("TEST_SIMULATION", result.getRulesetKey());
        assertNotNull(result.getMatchedRules());
        assertFalse(result.getMatchedRules().isEmpty());
        assertNotNull(result.getExplanation());
        assertTrue(result.getExplanation().contains("High Amount Decline"));
    }

    @Test
    void testInvalidYaml() {
        String invalidYaml = "invalid: yaml: content: [";

        TransactionContext transaction = createTestTransaction(100);

        SimulationService.InvalidRulesetException ex = assertThrows(
                SimulationService.InvalidRulesetException.class,
                () -> simulationService.simulate(transaction, invalidYaml)
        );

        assertTrue(ex.getMessage().contains("Failed to parse"));
    }

    @Test
    void testEmptyRuleset() {
        String yaml = """
                key: EMPTY_TEST
                evaluation_type: AUTH
                rules: []
                """;

        TransactionContext transaction = createTestTransaction(100);

        // Empty ruleset should default to APPROVE
        SimulationService.SimulationResult result = simulationService.simulate(transaction, yaml);

        assertEquals("test-txn-100", result.getTransactionId());
        assertEquals("APPROVE", result.getDecision());
        assertEquals("EMPTY_TEST", result.getRulesetKey());
        assertTrue(result.getMatchedRules() == null || result.getMatchedRules().isEmpty());
    }

    @Test
    void testMultipleConditions() {
        String yaml = """
                key: MULTI_CONDITION_TEST
                evaluation_type: AUTH
                rules:
                  - id: nigeria-high-amount
                    name: "Nigeria High Amount"
                    action: DECLINE
                    priority: 100
                    conditions:
                      - field: amount
                        operator: gt
                        value: 1000
                      - field: country_code
                        operator: in
                        values: [NG, RU, PK]
                      - field: card_present
                        operator: eq
                        value: false
                """;

        TransactionContext transaction = createTestTransaction(5000);
        transaction.setCountryCode("NG");

        SimulationService.SimulationResult result = simulationService.simulate(transaction, yaml);

        assertEquals("test-txn-5000", result.getTransactionId());
        assertEquals("DECLINE", result.getDecision());
        assertEquals("MULTI_CONDITION_TEST", result.getRulesetKey());
        assertNotNull(result.getMatchedRules());
        assertFalse(result.getMatchedRules().isEmpty());
        assertTrue(result.getExplanation().contains("Nigeria High Amount"));
    }

    @Test
    void testSimulationResultStructure() {
        // Test that SimulationResult can be constructed with all fields
        SimulationService.SimulationResult result = new SimulationService.SimulationResult();
        result.setTransactionId("test-123");
        result.setDecision("DECLINE");
        result.setRulesetKey("TEST");
        result.setRulesetVersion(1);
        result.setEvaluationTimeMs(5);

        assertEquals("test-123", result.getTransactionId());
        assertEquals("DECLINE", result.getDecision());
        assertEquals("TEST", result.getRulesetKey());
        assertEquals(1, result.getRulesetVersion());
        assertEquals(5, result.getEvaluationTimeMs());
    }

    private TransactionContext createTestTransaction(int amount) {
        TransactionContext tx = new TransactionContext();
        tx.setTransactionId("test-txn-" + amount);
        tx.setAmount(new java.math.BigDecimal(amount));
        tx.setCurrency("USD");
        tx.setCountryCode("US");
        tx.setCardPresent(false);
        tx.setTransactionType("PURCHASE");
        return tx;
    }
}
