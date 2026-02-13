package com.fraud.engine.velocity;

import com.fraud.engine.domain.Decision;
import com.fraud.engine.domain.TransactionContext;
import com.fraud.engine.domain.VelocityConfig;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for VelocityService.
 * Tests velocity checking with real Redis connection (requires Redis running).
 */
@QuarkusTest
class VelocityServiceTest {

    @Inject
    VelocityService velocityService;

    @Test
    void testCheckVelocity_BelowThreshold() {
        String uniqueCard = "test-card-below-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        TransactionContext txn = createTransaction(uniqueCard);
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 10);
        config.setAction("DECLINE");

        // Execute multiple times - should stay below threshold
        Decision.VelocityResult result1 = velocityService.checkVelocity(txn, config);
        Decision.VelocityResult result2 = velocityService.checkVelocity(txn, config);
        Decision.VelocityResult result3 = velocityService.checkVelocity(txn, config);

        // Verify
        assertThat(result1.getDimension()).isEqualTo("card_hash");
        assertThat(result1.getCount()).isEqualTo(1);
        assertThat(result1.getThreshold()).isEqualTo(10);
        assertThat(result1.getWindowSeconds()).isEqualTo(3600);
        assertThat(result1.isExceeded()).isFalse();

        assertThat(result2.getCount()).isEqualTo(2);
        assertThat(result3.getCount()).isEqualTo(3);
    }

    @Test
    void testCheckVelocity_ExceedsThreshold() {
        String uniqueCard = "test-card-high-" + System.currentTimeMillis();
        TransactionContext txn = createTransaction(uniqueCard);
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 3);
        config.setAction("DECLINE");

        // Execute until we exceed threshold
        Decision.VelocityResult result1 = velocityService.checkVelocity(txn, config);
        Decision.VelocityResult result2 = velocityService.checkVelocity(txn, config);
        Decision.VelocityResult result3 = velocityService.checkVelocity(txn, config);
        Decision.VelocityResult result4 = velocityService.checkVelocity(txn, config);

        // Verify
        assertThat(result1.isExceeded()).isFalse();
        assertThat(result2.isExceeded()).isFalse();
        assertThat(result3.isExceeded()).isTrue(); // At threshold
        assertThat(result4.isExceeded()).isTrue(); // Above threshold
    }

    @Test
    void testCheckVelocity_UsesDefaultsWhenNotSpecified() {
        String uniqueCard = "test-card-default-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        TransactionContext txn = createTransaction(uniqueCard);
        VelocityConfig config = new VelocityConfig("card_hash", 0, 0); // Use defaults

        Decision.VelocityResult result = velocityService.checkVelocity(txn, config);

        // Verify - should use injected defaults (3600, 10)
        assertThat(result.getWindowSeconds()).isEqualTo(3600);
        assertThat(result.getThreshold()).isEqualTo(10);
    }

    @Test
    void testCheckVelocity_DifferentDimensionsAreIndependent() {
        // Use unique values to avoid Redis state collisions
        String uniqueCard = "test-card-dim-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 100000);
        BigDecimal uniqueAmount = BigDecimal.valueOf(System.currentTimeMillis() % 100000);

        TransactionContext txn1 = createTransaction(uniqueCard);
        TransactionContext txn2 = createTransaction(uniqueCard);
        txn2.setAmount(uniqueAmount); // Unique amount for this test run

        VelocityConfig cardHashConfig = new VelocityConfig("card_hash", 3600, 5);
        VelocityConfig amountConfig = new VelocityConfig("amount", 3600, 5);

        // Check with card_hash dimension
        Decision.VelocityResult cardResult = velocityService.checkVelocity(txn1, cardHashConfig);

        // Check with amount dimension - should be independent
        Decision.VelocityResult amountResult = velocityService.checkVelocity(txn2, amountConfig);

        // Both should have count 1 (different dimensions and values)
        assertThat(cardResult.getCount()).isEqualTo(1);
        assertThat(amountResult.getCount()).isEqualTo(1);
    }

    @Test
    void testGetDefaultWindowSeconds() {
        assertThat(velocityService.getDefaultWindowSeconds()).isEqualTo(3600);
    }

    @Test
    void testGetDefaultThreshold() {
        assertThat(velocityService.getDefaultThreshold()).isEqualTo(10);
    }

    @Test
    void testGetCurrentCount() {
        String uniqueKey = "test-count-" + System.currentTimeMillis();

        // Count should start at 0
        long count = velocityService.getCurrentCount("vel:global:card_hash:" + uniqueKey);
        assertThat(count).isEqualTo(0);
    }

    @Test
    void testResetVelocity() {
        String uniqueCard = "test-card-reset-" + System.currentTimeMillis();
        TransactionContext txn = createTransaction(uniqueCard);
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 10);

        // Increment a few times
        velocityService.checkVelocity(txn, config);
        velocityService.checkVelocity(txn, config);

        // Get count
        long countBefore = velocityService.getCurrentCount("vel:global:card_hash:" + uniqueCard);
        assertThat(countBefore).isGreaterThan(0);

        // Reset
        velocityService.resetVelocity("vel:global:card_hash:" + uniqueCard);

        // Count should be 0 now
        long countAfter = velocityService.getCurrentCount("vel:global:card_hash:" + uniqueCard);
        assertThat(countAfter).isEqualTo(0);
    }

    @Test
    void testBuildVelocityKey_WithCardHash() {
        String uniqueCard = "test-card-key-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        TransactionContext txn = createTransaction(uniqueCard);
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 10);

        Decision.VelocityResult result = velocityService.checkVelocity(txn, config);

        // Just verify it works without throwing
        assertThat(result).isNotNull();
        assertThat(result.getDimension()).isEqualTo("card_hash");
    }

    @Test
    void testBuildVelocityKey_WithAmount() {
        String uniqueCard = "test-card-amount-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        TransactionContext txn = createTransaction(uniqueCard);
        txn.setAmount(BigDecimal.valueOf(123.45));
        VelocityConfig config = new VelocityConfig("amount", 3600, 10);

        Decision.VelocityResult result = velocityService.checkVelocity(txn, config);

        assertThat(result.getDimension()).isEqualTo("amount");
    }

    @Test
    void testBuildVelocityKey_WithSpecialCharacters() {
        String uniqueCard = "test-card-special-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        TransactionContext txn = createTransaction(uniqueCard);
        txn.setCardHash("abc@123#$"); // Special characters
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 10);

        // Should handle special characters gracefully
        Decision.VelocityResult result = velocityService.checkVelocity(txn, config);

        assertThat(result).isNotNull();
    }

    @Test
    void testMultipleTransactionsSameCard() {
        String uniqueCard = "test-card-multi-" + System.currentTimeMillis();
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 5);

        // Simulate multiple transactions with same card
        for (int i = 1; i <= 5; i++) {
            TransactionContext txn = createTransaction(uniqueCard);
            Decision.VelocityResult result = velocityService.checkVelocity(txn, config);
            assertThat(result.getCount()).isEqualTo(i);
        }
    }

    @Test
    void testVelocityWithDifferentCards() {
        String randomSuffix = "-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 10000);
        VelocityConfig config = new VelocityConfig("card_hash", 3600, 10);

        TransactionContext txn1 = createTransaction("card-A" + randomSuffix);
        TransactionContext txn2 = createTransaction("card-B" + randomSuffix);

        Decision.VelocityResult result1 = velocityService.checkVelocity(txn1, config);
        Decision.VelocityResult result2 = velocityService.checkVelocity(txn2, config);

        // Each card should have independent count
        assertThat(result1.getCount()).isEqualTo(1);
        assertThat(result2.getCount()).isEqualTo(1);
    }

    @Test
    void testGetDimensionValue_FromVariousFields() {
        TransactionContext txn = createTransaction("test-card-dim");
        txn.setMerchantId("merch-123");
        txn.setCountryCode("IN");
        txn.setAmount(BigDecimal.valueOf(500.00));

        VelocityConfig merchantConfig = new VelocityConfig("merchant_id", 3600, 10);
        VelocityConfig countryConfig = new VelocityConfig("country_code", 3600, 10);
        VelocityConfig amountConfig = new VelocityConfig("amount", 3600, 10);

        Decision.VelocityResult merchantResult = velocityService.checkVelocity(txn, merchantConfig);
        Decision.VelocityResult countryResult = velocityService.checkVelocity(txn, countryConfig);
        Decision.VelocityResult amountResult = velocityService.checkVelocity(txn, amountConfig);

        assertThat(merchantResult.getDimension()).isEqualTo("merchant_id");
        assertThat(countryResult.getDimension()).isEqualTo("country_code");
        assertThat(amountResult.getDimension()).isEqualTo("amount");
    }

    // === Helper Methods ===

    private TransactionContext createTransaction(String cardHash) {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-" + System.currentTimeMillis());
        txn.setCardHash(cardHash);
        txn.setAmount(BigDecimal.valueOf(100.00));
        txn.setCurrency("USD");
        txn.setCountryCode("US");
        return txn;
    }
}
