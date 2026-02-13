package com.fraud.engine.loader;

import com.fraud.engine.dto.FieldRegistryEntry;
import com.fraud.engine.domain.FieldRegistry;

import java.util.ArrayList;
import java.util.List;

/**
 * Builtin field registry providing the 26 standard fields as fallback.
 * <p>
 * This class provides hardcoded field definitions that match the constants
 * in {@link FieldRegistry}. Field IDs start from 1, not 0.
 * Used when S3 is unavailable or as initial bootstrap.
 */
public final class BuiltinFieldRegistry {

    private static final List<FieldRegistryEntry> BUILTIN_FIELDS;

    static {
        List<FieldRegistryEntry> fields = new ArrayList<>(26);

        // Transaction fields (1-4)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.TRANSACTION_ID, "transaction_id", "Transaction ID",
                "Unique transaction identifier", "STRING",
                List.of("EQ", "NE"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CARD_HASH, "card_hash", "Card Hash",
                "Hashed card identifier", "STRING",
                List.of("EQ", "NE"), false, true
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.AMOUNT, "amount", "Amount",
                "Transaction amount", "NUMBER",
                List.of("EQ", "GT", "GTE", "LT", "LTE", "BETWEEN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CURRENCY, "currency", "Currency",
                "Transaction currency code", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));

        // Merchant fields (5-8)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.MERCHANT_ID, "merchant_id", "Merchant ID",
                "Unique merchant identifier", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.MERCHANT_NAME, "merchant_name", "Merchant Name",
                "Merchant business name", "STRING",
                List.of("EQ", "NE", "CONTAINS"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.MERCHANT_CATEGORY, "merchant_category", "Merchant Category",
                "Merchant business category", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.MERCHANT_CATEGORY_CODE, "merchant_category_code", "MCC",
                "Merchant Category Code", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));

        // Transaction attributes (9-12)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CARD_PRESENT, "card_present", "Card Present",
                "Whether physical card was present", "BOOLEAN",
                List.of("EQ", "NE"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.TRANSACTION_TYPE, "transaction_type", "Transaction Type",
                "Type of transaction (e.g., PURCHASE, REFUND)", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.ENTRY_MODE, "entry_mode", "Entry Mode",
                "How card data was entered (e.g., CHIP, SWIPE, ECOM)", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.COUNTRY_CODE, "country_code", "Country Code",
                "ISO country code of transaction", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));

        // Digital footprint (13-16)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.IP_ADDRESS, "ip_address", "IP Address",
                "IP address of transaction initiator", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), true, true
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.DEVICE_ID, "device_id", "Device ID",
                "Unique device identifier", "STRING",
                List.of("EQ", "NE"), false, true
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.EMAIL, "email", "Email",
                "Email address associated with transaction", "STRING",
                List.of("EQ", "NE", "CONTAINS", "ENDS_WITH"), false, true
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.PHONE, "phone", "Phone",
                "Phone number associated with transaction", "STRING",
                List.of("EQ", "NE"), false, true
        ));

        // Timestamp and billing (17-20)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.TIMESTAMP, "timestamp", "Timestamp",
                "Transaction timestamp", "NUMBER",
                List.of("EQ", "GT", "GTE", "LT", "LTE", "BETWEEN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.BILLING_CITY, "billing_city", "Billing City",
                "Billing address city", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.BILLING_COUNTRY, "billing_country", "Billing Country",
                "Billing address country", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.BILLING_POSTAL_CODE, "billing_postal_code", "Billing Postal Code",
                "Billing address postal code", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, true
        ));

        // Shipping (21-23)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.SHIPPING_CITY, "shipping_city", "Shipping City",
                "Shipping address city", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.SHIPPING_COUNTRY, "shipping_country", "Shipping Country",
                "Shipping address country", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.SHIPPING_POSTAL_CODE, "shipping_postal_code", "Shipping Postal Code",
                "Shipping address postal code", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, true
        ));

        // Card scope fields (24-26)
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CARD_NETWORK, "card_network", "Card Network",
                "Card network (e.g., VISA, MC, AMEX)", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CARD_BIN, "card_bin", "Card BIN",
                "Bank Identification Number (first 6-8 digits)", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN", "STARTS_WITH"), false, false
        ));
        fields.add(new FieldRegistryEntry(
                FieldRegistry.CARD_LOGO, "card_logo", "Card Logo",
                "Card brand logo identifier", "STRING",
                List.of("EQ", "NE", "IN", "NOT_IN"), false, false
        ));

        BUILTIN_FIELDS = List.copyOf(fields);
    }

    /**
     * Returns the list of builtin field definitions.
     *
     * @return unmodifiable list of 26 standard field entries
     */
    public static List<FieldRegistryEntry> getFields() {
        return BUILTIN_FIELDS;
    }

    /**
     * Returns the count of builtin fields.
     *
     * @return always 26
     */
    public static int getFieldCount() {
        return BUILTIN_FIELDS.size();
    }

    // Prevent instantiation
    private BuiltinFieldRegistry() {
        throw new UnsupportedOperationException("Utility class");
    }
}
