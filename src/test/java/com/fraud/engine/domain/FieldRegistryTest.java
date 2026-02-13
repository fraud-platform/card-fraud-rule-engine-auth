package com.fraud.engine.domain;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for FieldRegistry.
 * <p>
 * Verifies the centralized field ID registry used for high-performance rule evaluation.
 */
class FieldRegistryTest {

    @Test
    void testFromName_StandardFields() {
        assertThat(FieldRegistry.fromName("transaction_id")).isEqualTo(FieldRegistry.TRANSACTION_ID);
        assertThat(FieldRegistry.fromName("card_hash")).isEqualTo(FieldRegistry.CARD_HASH);
        assertThat(FieldRegistry.fromName("amount")).isEqualTo(FieldRegistry.AMOUNT);
        assertThat(FieldRegistry.fromName("currency")).isEqualTo(FieldRegistry.CURRENCY);
        assertThat(FieldRegistry.fromName("merchant_id")).isEqualTo(FieldRegistry.MERCHANT_ID);
        assertThat(FieldRegistry.fromName("merchant_name")).isEqualTo(FieldRegistry.MERCHANT_NAME);
        assertThat(FieldRegistry.fromName("merchant_category")).isEqualTo(FieldRegistry.MERCHANT_CATEGORY);
        assertThat(FieldRegistry.fromName("merchant_category_code")).isEqualTo(FieldRegistry.MERCHANT_CATEGORY_CODE);
        assertThat(FieldRegistry.fromName("card_present")).isEqualTo(FieldRegistry.CARD_PRESENT);
        assertThat(FieldRegistry.fromName("transaction_type")).isEqualTo(FieldRegistry.TRANSACTION_TYPE);
        assertThat(FieldRegistry.fromName("entry_mode")).isEqualTo(FieldRegistry.ENTRY_MODE);
        assertThat(FieldRegistry.fromName("country_code")).isEqualTo(FieldRegistry.COUNTRY_CODE);
        assertThat(FieldRegistry.fromName("ip_address")).isEqualTo(FieldRegistry.IP_ADDRESS);
        assertThat(FieldRegistry.fromName("device_id")).isEqualTo(FieldRegistry.DEVICE_ID);
        assertThat(FieldRegistry.fromName("email")).isEqualTo(FieldRegistry.EMAIL);
        assertThat(FieldRegistry.fromName("phone")).isEqualTo(FieldRegistry.PHONE);
        assertThat(FieldRegistry.fromName("timestamp")).isEqualTo(FieldRegistry.TIMESTAMP);
        assertThat(FieldRegistry.fromName("billing_city")).isEqualTo(FieldRegistry.BILLING_CITY);
        assertThat(FieldRegistry.fromName("billing_country")).isEqualTo(FieldRegistry.BILLING_COUNTRY);
        assertThat(FieldRegistry.fromName("billing_postal_code")).isEqualTo(FieldRegistry.BILLING_POSTAL_CODE);
        assertThat(FieldRegistry.fromName("shipping_city")).isEqualTo(FieldRegistry.SHIPPING_CITY);
        assertThat(FieldRegistry.fromName("shipping_country")).isEqualTo(FieldRegistry.SHIPPING_COUNTRY);
        assertThat(FieldRegistry.fromName("shipping_postal_code")).isEqualTo(FieldRegistry.SHIPPING_POSTAL_CODE);

        // Scope-related fields
        assertThat(FieldRegistry.fromName("card_network")).isEqualTo(FieldRegistry.CARD_NETWORK);
        assertThat(FieldRegistry.fromName("card_bin")).isEqualTo(FieldRegistry.CARD_BIN);
        assertThat(FieldRegistry.fromName("card_logo")).isEqualTo(FieldRegistry.CARD_LOGO);
    }

    @Test
    void testFromName_Aliases() {
        assertThat(FieldRegistry.fromName("txn_id")).isEqualTo(FieldRegistry.TRANSACTION_ID);
        assertThat(FieldRegistry.fromName("card")).isEqualTo(FieldRegistry.CARD_HASH);
        assertThat(FieldRegistry.fromName("merch_id")).isEqualTo(FieldRegistry.MERCHANT_ID);
        assertThat(FieldRegistry.fromName("merch_category")).isEqualTo(FieldRegistry.MERCHANT_CATEGORY);
        assertThat(FieldRegistry.fromName("mcc")).isEqualTo(FieldRegistry.MERCHANT_CATEGORY_CODE);
        assertThat(FieldRegistry.fromName("ip")).isEqualTo(FieldRegistry.IP_ADDRESS);
        assertThat(FieldRegistry.fromName("device")).isEqualTo(FieldRegistry.DEVICE_ID);

        // Scope field aliases
        assertThat(FieldRegistry.fromName("network")).isEqualTo(FieldRegistry.CARD_NETWORK);
        assertThat(FieldRegistry.fromName("bin")).isEqualTo(FieldRegistry.CARD_BIN);
        assertThat(FieldRegistry.fromName("logo")).isEqualTo(FieldRegistry.CARD_LOGO);
    }

    @Test
    void testFromName_UnknownField() {
        assertThat(FieldRegistry.fromName("unknown_field")).isEqualTo(FieldRegistry.UNKNOWN);
        assertThat(FieldRegistry.fromName("")).isEqualTo(FieldRegistry.UNKNOWN);
        assertThat(FieldRegistry.fromName(null)).isEqualTo(FieldRegistry.UNKNOWN);
    }

    @Test
    void testGetName_AllStandardFields() {
        assertThat(FieldRegistry.getName(FieldRegistry.TRANSACTION_ID)).isEqualTo("transaction_id");
        assertThat(FieldRegistry.getName(FieldRegistry.CARD_HASH)).isEqualTo("card_hash");
        assertThat(FieldRegistry.getName(FieldRegistry.AMOUNT)).isEqualTo("amount");
        assertThat(FieldRegistry.getName(FieldRegistry.CURRENCY)).isEqualTo("currency");
        assertThat(FieldRegistry.getName(FieldRegistry.MERCHANT_ID)).isEqualTo("merchant_id");
        assertThat(FieldRegistry.getName(FieldRegistry.MERCHANT_NAME)).isEqualTo("merchant_name");
        assertThat(FieldRegistry.getName(FieldRegistry.MERCHANT_CATEGORY)).isEqualTo("merchant_category");
        assertThat(FieldRegistry.getName(FieldRegistry.MERCHANT_CATEGORY_CODE)).isEqualTo("merchant_category_code");
        assertThat(FieldRegistry.getName(FieldRegistry.CARD_PRESENT)).isEqualTo("card_present");
        assertThat(FieldRegistry.getName(FieldRegistry.TRANSACTION_TYPE)).isEqualTo("transaction_type");
        assertThat(FieldRegistry.getName(FieldRegistry.ENTRY_MODE)).isEqualTo("entry_mode");
        assertThat(FieldRegistry.getName(FieldRegistry.COUNTRY_CODE)).isEqualTo("country_code");
        assertThat(FieldRegistry.getName(FieldRegistry.IP_ADDRESS)).isEqualTo("ip_address");
        assertThat(FieldRegistry.getName(FieldRegistry.DEVICE_ID)).isEqualTo("device_id");
        assertThat(FieldRegistry.getName(FieldRegistry.EMAIL)).isEqualTo("email");
        assertThat(FieldRegistry.getName(FieldRegistry.PHONE)).isEqualTo("phone");
        assertThat(FieldRegistry.getName(FieldRegistry.TIMESTAMP)).isEqualTo("timestamp");
        assertThat(FieldRegistry.getName(FieldRegistry.BILLING_CITY)).isEqualTo("billing_city");
        assertThat(FieldRegistry.getName(FieldRegistry.BILLING_COUNTRY)).isEqualTo("billing_country");
        assertThat(FieldRegistry.getName(FieldRegistry.BILLING_POSTAL_CODE)).isEqualTo("billing_postal_code");
        assertThat(FieldRegistry.getName(FieldRegistry.SHIPPING_CITY)).isEqualTo("shipping_city");
        assertThat(FieldRegistry.getName(FieldRegistry.SHIPPING_COUNTRY)).isEqualTo("shipping_country");
        assertThat(FieldRegistry.getName(FieldRegistry.SHIPPING_POSTAL_CODE)).isEqualTo("shipping_postal_code");

        // Scope-related fields
        assertThat(FieldRegistry.getName(FieldRegistry.CARD_NETWORK)).isEqualTo("card_network");
        assertThat(FieldRegistry.getName(FieldRegistry.CARD_BIN)).isEqualTo("card_bin");
        assertThat(FieldRegistry.getName(FieldRegistry.CARD_LOGO)).isEqualTo("card_logo");
    }

    @Test
    void testGetName_UnknownFieldIds() {
        // Zero field ID (not valid in 1-based indexing)
        assertThat(FieldRegistry.getName(0)).isEqualTo("UNKNOWN");

        // Negative field ID
        assertThat(FieldRegistry.getName(-1)).isEqualTo("UNKNOWN");
        assertThat(FieldRegistry.getName(-999)).isEqualTo("UNKNOWN");

        // Out of range field ID (beyond FIELD_COUNT)
        assertThat(FieldRegistry.getName(27)).isEqualTo("UNKNOWN");
        assertThat(FieldRegistry.getName(100)).isEqualTo("UNKNOWN");
        assertThat(FieldRegistry.getName(Integer.MAX_VALUE)).isEqualTo("UNKNOWN");
    }

    @Test
    void testIsValid() {
        // Valid field IDs (1-based indexing)
        assertThat(FieldRegistry.isValid(FieldRegistry.TRANSACTION_ID)).isTrue();
        assertThat(FieldRegistry.isValid(1)).isTrue();
        assertThat(FieldRegistry.isValid(FieldRegistry.FIELD_COUNT - 1)).isTrue();

        // Invalid field IDs
        assertThat(FieldRegistry.isValid(0)).isFalse();  // 0 is not valid in 1-based indexing
        assertThat(FieldRegistry.isValid(-1)).isFalse();
        assertThat(FieldRegistry.isValid(FieldRegistry.FIELD_COUNT)).isFalse();
        assertThat(FieldRegistry.isValid(100)).isFalse();
    }

    @Test
    void testGetFieldCount() {
        // FIELD_COUNT is 27 (26 standard fields + 1 for 1-based indexing)
        assertThat(FieldRegistry.getFieldCount()).isEqualTo(27);
    }

    @Test
    void testFromNameGetNameRoundTrip() {
        // Verify that fromName and getName are consistent for all standard fields
        String[] fieldNames = {
            "transaction_id", "card_hash", "amount", "currency", "merchant_id",
            "merchant_name", "merchant_category", "merchant_category_code", "card_present",
            "transaction_type", "entry_mode", "country_code", "ip_address", "device_id",
            "email", "phone", "timestamp", "billing_city", "billing_country",
            "billing_postal_code", "shipping_city", "shipping_country", "shipping_postal_code",
            "card_network", "card_bin", "card_logo"
        };

        for (String fieldName : fieldNames) {
            int fieldId = FieldRegistry.fromName(fieldName);
            assertThat(fieldId).isNotEqualTo(FieldRegistry.UNKNOWN);
            assertThat(FieldRegistry.getName(fieldId)).isEqualTo(fieldName);
        }
    }

    @Test
    void testFieldIdConstantsAreSequential() {
        // Verify field IDs are sequential starting from 1 (1-based indexing)
        assertThat(FieldRegistry.TRANSACTION_ID).isEqualTo(1);
        assertThat(FieldRegistry.CARD_HASH).isEqualTo(2);
        assertThat(FieldRegistry.AMOUNT).isEqualTo(3);
        assertThat(FieldRegistry.CURRENCY).isEqualTo(4);
        assertThat(FieldRegistry.MERCHANT_ID).isEqualTo(5);
        assertThat(FieldRegistry.MERCHANT_NAME).isEqualTo(6);
        assertThat(FieldRegistry.MERCHANT_CATEGORY).isEqualTo(7);
        assertThat(FieldRegistry.MERCHANT_CATEGORY_CODE).isEqualTo(8);
        assertThat(FieldRegistry.CARD_PRESENT).isEqualTo(9);
        assertThat(FieldRegistry.TRANSACTION_TYPE).isEqualTo(10);
        assertThat(FieldRegistry.ENTRY_MODE).isEqualTo(11);
        assertThat(FieldRegistry.COUNTRY_CODE).isEqualTo(12);
        assertThat(FieldRegistry.IP_ADDRESS).isEqualTo(13);
        assertThat(FieldRegistry.DEVICE_ID).isEqualTo(14);
        assertThat(FieldRegistry.EMAIL).isEqualTo(15);
        assertThat(FieldRegistry.PHONE).isEqualTo(16);
        assertThat(FieldRegistry.TIMESTAMP).isEqualTo(17);
        assertThat(FieldRegistry.BILLING_CITY).isEqualTo(18);
        assertThat(FieldRegistry.BILLING_COUNTRY).isEqualTo(19);
        assertThat(FieldRegistry.BILLING_POSTAL_CODE).isEqualTo(20);
        assertThat(FieldRegistry.SHIPPING_CITY).isEqualTo(21);
        assertThat(FieldRegistry.SHIPPING_COUNTRY).isEqualTo(22);
        assertThat(FieldRegistry.SHIPPING_POSTAL_CODE).isEqualTo(23);

        // Scope-related fields
        assertThat(FieldRegistry.CARD_NETWORK).isEqualTo(24);
        assertThat(FieldRegistry.CARD_BIN).isEqualTo(25);
        assertThat(FieldRegistry.CARD_LOGO).isEqualTo(26);
    }

    @Test
    void testFieldCountMatchesLastId() {
        // FIELD_COUNT should be one more than the last valid field ID
        assertThat(FieldRegistry.FIELD_COUNT).isEqualTo(FieldRegistry.CARD_LOGO + 1);
    }

    @Test
    void testCannotInstantiate() {
        // Verify that FieldRegistry cannot be instantiated (utility class)
        NoSuchMethodException exception = org.junit.jupiter.api.Assertions.assertThrows(
            NoSuchMethodException.class,
            () -> FieldRegistry.class.getConstructor()
        );
        assertThat(exception).isNotNull();
    }
}
