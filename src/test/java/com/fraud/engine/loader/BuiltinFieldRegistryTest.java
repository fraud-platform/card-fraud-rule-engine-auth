package com.fraud.engine.loader;

import com.fraud.engine.domain.FieldRegistry;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for BuiltinFieldRegistry.
 * <p>
 * Verifies that the builtin fallback registry contains all 26 standard fields
 * and matches the constants in {@link FieldRegistry}.
 */
class BuiltinFieldRegistryTest {

    @Test
    void testGetFields_Returns26Fields() {
        assertThat(BuiltinFieldRegistry.getFields())
                .hasSize(26);
    }

    @Test
    void testGetFieldCount_Returns26() {
        assertThat(BuiltinFieldRegistry.getFieldCount())
                .isEqualTo(26);
    }

    @Test
    void testBuiltinFieldsMatchFieldRegistry() {
        var fields = BuiltinFieldRegistry.getFields();

        // Verify all standard fields are present
        assertThat(fields)
                .extracting("fieldId")
                .containsExactlyInAnyOrder(
                        FieldRegistry.TRANSACTION_ID,
                        FieldRegistry.CARD_HASH,
                        FieldRegistry.AMOUNT,
                        FieldRegistry.CURRENCY,
                        FieldRegistry.MERCHANT_ID,
                        FieldRegistry.MERCHANT_NAME,
                        FieldRegistry.MERCHANT_CATEGORY,
                        FieldRegistry.MERCHANT_CATEGORY_CODE,
                        FieldRegistry.CARD_PRESENT,
                        FieldRegistry.TRANSACTION_TYPE,
                        FieldRegistry.ENTRY_MODE,
                        FieldRegistry.COUNTRY_CODE,
                        FieldRegistry.IP_ADDRESS,
                        FieldRegistry.DEVICE_ID,
                        FieldRegistry.EMAIL,
                        FieldRegistry.PHONE,
                        FieldRegistry.TIMESTAMP,
                        FieldRegistry.BILLING_CITY,
                        FieldRegistry.BILLING_COUNTRY,
                        FieldRegistry.BILLING_POSTAL_CODE,
                        FieldRegistry.SHIPPING_CITY,
                        FieldRegistry.SHIPPING_COUNTRY,
                        FieldRegistry.SHIPPING_POSTAL_CODE,
                        FieldRegistry.CARD_NETWORK,
                        FieldRegistry.CARD_BIN,
                        FieldRegistry.CARD_LOGO
                );
    }

    @Test
    void testAllFieldsHaveRequiredProperties() {
        var fields = BuiltinFieldRegistry.getFields();

        // Verify each field has required properties
        assertThat(fields)
                .allSatisfy(field -> {
                    assertThat(field.getFieldId()).isNotNegative();
                    assertThat(field.getFieldKey()).isNotEmpty();
                    assertThat(field.getDisplayName()).isNotEmpty();
                    assertThat(field.getDescription()).isNotEmpty();
                    assertThat(field.getDataType()).isNotEmpty();
                    assertThat(field.getAllowedOperators()).isNotEmpty();
                });
    }

    @Test
    void testSensitiveFieldsAreMarked() {
        var fields = BuiltinFieldRegistry.getFields();

        // Check that sensitive fields are marked correctly
        assertThat(fields)
                .filteredOn("isSensitive", true)
                .extracting("fieldKey")
                .contains("card_hash", "ip_address", "device_id", "email", "phone",
                          "billing_postal_code", "shipping_postal_code");
    }

    @Test
    void testFieldKeysMatchFieldRegistryNames() {
        var fields = BuiltinFieldRegistry.getFields();

        // Verify field keys match FieldRegistry names
        assertThat(fields)
                .allSatisfy(field -> {
                    String expectedName = FieldRegistry.getName(field.getFieldId());
                    if (!"UNKNOWN".equals(expectedName)) {
                        assertThat(field.getFieldKey()).isEqualTo(expectedName);
                    }
                });
    }

    @Test
    void testCannotInstantiate() {
        // Verify that BuiltinFieldRegistry cannot be instantiated (utility class)
        NoSuchMethodException exception = org.junit.jupiter.api.Assertions.assertThrows(
                NoSuchMethodException.class,
                () -> BuiltinFieldRegistry.class.getConstructor()
        );
        assertThat(exception).isNotNull();
    }
}
