package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SuppressWarnings("deprecation")
class TransactionContextTest {

    @Test
    void testTransactionContextCreation() {
        TransactionContext txn = new TransactionContext();

        txn.setTransactionId("txn-123");
        txn.setCardHash("card-abc123");
        txn.setAmount(BigDecimal.valueOf(150.00));
        txn.setCurrency("USD");
        txn.setMerchantCategoryCode("5411");
        txn.setCountryCode("US");

        assertThat(txn.getTransactionId()).isEqualTo("txn-123");
        assertThat(txn.getCardHash()).isEqualTo("card-abc123");
        assertThat(txn.getAmount()).isEqualTo(BigDecimal.valueOf(150.00));
        assertThat(txn.getCurrency()).isEqualTo("USD");
        assertThat(txn.getMerchantCategoryCode()).isEqualTo("5411");
        assertThat(txn.getCountryCode()).isEqualTo("US");
    }

    @Test
    void testToEvaluationContext_BasicFields() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");
        txn.setCardHash("card-abc123");
        txn.setAmount(BigDecimal.valueOf(150.00));
        txn.setCurrency("USD");
        txn.setMerchantId("merchant-001");
        txn.setMerchantName("Test Store");
        txn.setMerchantCategoryCode("5411");
        txn.setCardPresent(true);
        txn.setTransactionType("PURCHASE");
        txn.setEntryMode("CHIP");
        txn.setCountryCode("US");
        txn.setIpAddress("192.168.1.1");
        txn.setDeviceId("device-001");
        txn.setEmail("test@example.com");
        txn.setPhone("+1234567890");
        txn.setTimestamp(Instant.now());

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("transaction_id")).isEqualTo("txn-123");
        assertThat(context.get("card_hash")).isEqualTo("card-abc123");
        assertThat(context.get("amount")).isEqualTo(BigDecimal.valueOf(150.00));
        assertThat(context.get("currency")).isEqualTo("USD");
        assertThat(context.get("merchant_id")).isEqualTo("merchant-001");
        assertThat(context.get("merchant_name")).isEqualTo("Test Store");
        assertThat(context.get("merchant_category_code")).isEqualTo("5411");
        assertThat(context.get("card_present")).isEqualTo(true);
        assertThat(context.get("transaction_type")).isEqualTo("PURCHASE");
        assertThat(context.get("entry_mode")).isEqualTo("CHIP");
        assertThat(context.get("country_code")).isEqualTo("US");
        assertThat(context.get("ip_address")).isEqualTo("192.168.1.1");
        assertThat(context.get("device_id")).isEqualTo("device-001");
        assertThat(context.get("email")).isEqualTo("test@example.com");
        assertThat(context.get("phone")).isEqualTo("+1234567890");
        assertThat(context).containsKey("timestamp");
    }

    @Test
    void testToEvaluationContext_IgnoresNullFields() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");
        txn.setCardHash(null);
        txn.setAmount(null);

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context).containsKey("transaction_id");
        assertThat(context).doesNotContainKey("card_hash");
        assertThat(context).doesNotContainKey("amount");
    }

    @Test
    void testToEvaluationContext_WithBillingAddress() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");

        TransactionContext.Address billingAddress = new TransactionContext.Address();
        billingAddress.setCity("New York");
        billingAddress.setCountry("US");
        billingAddress.setPostalCode("10001");
        txn.setBillingAddress(billingAddress);

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("billing_city")).isEqualTo("New York");
        assertThat(context.get("billing_country")).isEqualTo("US");
        assertThat(context.get("billing_postal_code")).isEqualTo("10001");
    }

    @Test
    void testToEvaluationContext_WithShippingAddress() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");

        TransactionContext.Address shippingAddress = new TransactionContext.Address();
        shippingAddress.setCity("Los Angeles");
        shippingAddress.setCountry("US");
        shippingAddress.setPostalCode("90001");
        txn.setShippingAddress(shippingAddress);

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("shipping_city")).isEqualTo("Los Angeles");
        assertThat(context.get("shipping_country")).isEqualTo("US");
        assertThat(context.get("shipping_postal_code")).isEqualTo("90001");
    }

    @Test
    void testToEvaluationContext_WithCustomFields() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");
        txn.addCustomField("previous_transaction_id", "txn-122");
        txn.addCustomField("customer_tier", "gold");

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("previous_transaction_id")).isEqualTo("txn-122");
        assertThat(context.get("customer_tier")).isEqualTo("gold");
    }

    @Test
    void testCustomFieldsMap() {
        TransactionContext txn = new TransactionContext();

        txn.addCustomField("key1", "value1");
        txn.addCustomField("key2", 42);

        assertThat(txn.getCustomFields()).hasSize(2);
        assertThat(txn.getCustomFields().get("key1")).isEqualTo("value1");
        assertThat(txn.getCustomFields().get("key2")).isEqualTo(42);
    }

    @Test
    void testCustomFieldsLazyAllocation() {
        TransactionContext txn = new TransactionContext();
        assertThat(txn.getCustomFieldsIfPresent()).isNull();

        txn.addCustomField("key", "value");

        assertThat(txn.getCustomFieldsIfPresent()).containsEntry("key", "value");
    }

    @Test
    void testAddressFields() {
        TransactionContext.Address address = new TransactionContext.Address();
        address.setStreet1("123 Main St");
        address.setStreet2("Apt 4B");
        address.setCity("New York");
        address.setState("NY");
        address.setPostalCode("10001");
        address.setCountry("US");

        assertThat(address.getStreet1()).isEqualTo("123 Main St");
        assertThat(address.getStreet2()).isEqualTo("Apt 4B");
        assertThat(address.getCity()).isEqualTo("New York");
        assertThat(address.getState()).isEqualTo("NY");
        assertThat(address.getPostalCode()).isEqualTo("10001");
        assertThat(address.getCountry()).isEqualTo("US");
    }

    @Test
    void testToEvaluationContext_EmptyCustomFields() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("custom_fields")).isNull();
    }

    @Test
    void testTimestamp() {
        TransactionContext txn = new TransactionContext();
        Instant now = Instant.now();
        txn.setTimestamp(now);

        assertThat(txn.getTimestamp()).isEqualTo(now);
    }

    @Test
    void testTimestampRawParsingIsLazy() {
        TransactionContext txn = new TransactionContext();
        String rawTimestamp = "2026-02-11T00:00:00Z";
        txn.setTimestampRaw(rawTimestamp);

        assertThat(txn.getField(TransactionContext.F_TIMESTAMP)).isEqualTo(rawTimestamp);
        assertThat(txn.getTimestamp()).isEqualTo(Instant.parse(rawTimestamp));
    }

    @Test
    void testEntryModeAndMerchantCategory() {
        TransactionContext txn = new TransactionContext();
        txn.setEntryMode("CONTACTLESS");
        txn.setMerchantCategory("Grocery");
        txn.setMerchantCategoryCode("5411");

        assertThat(txn.getEntryMode()).isEqualTo("CONTACTLESS");
        assertThat(txn.getMerchantCategory()).isEqualTo("Grocery");
        assertThat(txn.getMerchantCategoryCode()).isEqualTo("5411");
    }

    @Test
    void testArrayBackedFieldAccess() {
        TransactionContext txn = new TransactionContext();
        txn.setCardNetwork("VISA");
        txn.setCardBin("411111");
        txn.setCardLogo("VISA");

        assertThat(txn.getField(TransactionContext.F_CARD_NETWORK)).isEqualTo("VISA");
        assertThat(txn.getField(TransactionContext.F_CARD_BIN)).isEqualTo("411111");
        assertThat(txn.getField(TransactionContext.F_CARD_LOGO)).isEqualTo("VISA");

        txn.setField(0, "ignored");
        txn.setField(TransactionContext.F_COUNT, "ignored");
        assertThat(txn.getField(0)).isNull();
        assertThat(txn.getField(TransactionContext.F_COUNT)).isNull();
    }

    @Test
    void testToEvaluationContextIncludesDecisionAndScope() {
        TransactionContext txn = new TransactionContext();
        txn.setTransactionId("txn-123");
        txn.setDecision("DECLINE");
        txn.setCardNetwork("VISA");
        txn.setCardBin("411111");
        txn.setCardLogo("VISA");

        Map<String, Object> context = txn.toEvaluationContext();

        assertThat(context.get("decision")).isEqualTo("DECLINE");
        assertThat(context.get("card_network")).isEqualTo("VISA");
        assertThat(context.get("card_bin")).isEqualTo("411111");
        assertThat(context.get("card_logo")).isEqualTo("VISA");
    }
}
