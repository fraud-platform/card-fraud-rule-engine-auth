package com.fraud.engine.domain;

import java.util.HashMap;
import java.util.Map;

/**
 * Centralized registry for field identifiers used in rule evaluation.
 * <p>
 * This class provides a mapping between field names (as strings) and integer field IDs.
 * Using integer IDs instead of string names provides:
 * <ul>
 *   <li>Faster comparisons (int vs String)</li>
 *   <li>Better CPU branch prediction</li>
 *   <li>Reduced memory allocations</li>
 *   <li>Cache-friendly access patterns</li>
 * </ul>
 * <p>
 * This is now the single source of truth for field IDs. TransactionContext.F_* constants
 * reference these values, and ConditionCompiler uses {@link #fromName(String)} for lookup.
 *
 * @see TransactionContext - Uses the F_* constants which reference these values
 */
public final class FieldRegistry {

    // ========== Field IDs ==========
    // These match the constants in TransactionContext
    // Field IDs start from 1 (not 0) to align with rule-management

    public static final int TRANSACTION_ID = 1;
    public static final int CARD_HASH = 2;
    public static final int AMOUNT = 3;
    public static final int CURRENCY = 4;
    public static final int MERCHANT_ID = 5;
    public static final int MERCHANT_NAME = 6;
    public static final int MERCHANT_CATEGORY = 7;
    public static final int MERCHANT_CATEGORY_CODE = 8;
    public static final int CARD_PRESENT = 9;
    public static final int TRANSACTION_TYPE = 10;
    public static final int ENTRY_MODE = 11;
    public static final int COUNTRY_CODE = 12;
    public static final int IP_ADDRESS = 13;
    public static final int DEVICE_ID = 14;
    public static final int EMAIL = 15;
    public static final int PHONE = 16;
    public static final int TIMESTAMP = 17;
    public static final int BILLING_CITY = 18;
    public static final int BILLING_COUNTRY = 19;
    public static final int BILLING_POSTAL_CODE = 20;
    public static final int SHIPPING_CITY = 21;
    public static final int SHIPPING_COUNTRY = 22;
    public static final int SHIPPING_POSTAL_CODE = 23;

    // Scope-related fields for rule bucketing
    public static final int CARD_NETWORK = 24;
    public static final int CARD_BIN = 25;
    public static final int CARD_LOGO = 26;

    // Number of standard fields (max ID + 1)
    public static final int FIELD_COUNT = 27;

    // Field ID for unknown/custom fields (any field not in the standard list)
    public static final int UNKNOWN = 0;

    // ========== Name to ID Mapping ==========

    private static final Map<String, Integer> NAME_TO_ID;

    static {
        Map<String, Integer> map = new HashMap<>(32);

        // Standard fields
        map.put("transaction_id", TRANSACTION_ID);
        map.put("card_hash", CARD_HASH);
        map.put("amount", AMOUNT);
        map.put("currency", CURRENCY);
        map.put("merchant_id", MERCHANT_ID);
        map.put("merchant_name", MERCHANT_NAME);
        map.put("merchant_category", MERCHANT_CATEGORY);
        map.put("merchant_category_code", MERCHANT_CATEGORY_CODE);
        map.put("card_present", CARD_PRESENT);
        map.put("transaction_type", TRANSACTION_TYPE);
        map.put("entry_mode", ENTRY_MODE);
        map.put("country_code", COUNTRY_CODE);
        map.put("ip_address", IP_ADDRESS);
        map.put("device_id", DEVICE_ID);
        map.put("email", EMAIL);
        map.put("phone", PHONE);
        map.put("timestamp", TIMESTAMP);
        map.put("billing_city", BILLING_CITY);
        map.put("billing_country", BILLING_COUNTRY);
        map.put("billing_postal_code", BILLING_POSTAL_CODE);
        map.put("shipping_city", SHIPPING_CITY);
        map.put("shipping_country", SHIPPING_COUNTRY);
        map.put("shipping_postal_code", SHIPPING_POSTAL_CODE);
        map.put("timestamp", TIMESTAMP);

        // Scope-related fields
        map.put("card_network", CARD_NETWORK);
        map.put("card_bin", CARD_BIN);
        map.put("card_logo", CARD_LOGO);

        // Aliases for common field variations
        map.put("txn_id", TRANSACTION_ID);
        map.put("card", CARD_HASH);
        map.put("merch_id", MERCHANT_ID);
        map.put("merch_category", MERCHANT_CATEGORY);
        map.put("mcc", MERCHANT_CATEGORY_CODE);
        map.put("ip", IP_ADDRESS);
        map.put("device", DEVICE_ID);

        // Aliases for scope fields
        map.put("network", CARD_NETWORK);
        map.put("bin", CARD_BIN);
        map.put("logo", CARD_LOGO);

        NAME_TO_ID = Map.copyOf(map);
    }

    // ========== Public Methods ==========

    /**
     * Gets the field ID for a given field name.
     *
     * @param fieldName the field name (e.g., "card_hash", "amount")
     * @return the field ID, or {@link #UNKNOWN} if not found
     */
    public static int fromName(String fieldName) {
        if (fieldName == null) {
            return UNKNOWN;
        }
        Integer id = NAME_TO_ID.get(fieldName);
        return id != null ? id : UNKNOWN;
    }

    /**
     * Gets the field name for a given field ID.
     * <p>This is primarily used for debugging and logging.
     *
     * @param fieldId the field ID
     * @return the field name, or "UNKNOWN" if not found
     */
    public static String getName(int fieldId) {
        return switch (fieldId) {
            case TRANSACTION_ID -> "transaction_id";
            case CARD_HASH -> "card_hash";
            case AMOUNT -> "amount";
            case CURRENCY -> "currency";
            case MERCHANT_ID -> "merchant_id";
            case MERCHANT_NAME -> "merchant_name";
            case MERCHANT_CATEGORY -> "merchant_category";
            case MERCHANT_CATEGORY_CODE -> "merchant_category_code";
            case CARD_PRESENT -> "card_present";
            case TRANSACTION_TYPE -> "transaction_type";
            case ENTRY_MODE -> "entry_mode";
            case COUNTRY_CODE -> "country_code";
            case IP_ADDRESS -> "ip_address";
            case DEVICE_ID -> "device_id";
            case EMAIL -> "email";
            case PHONE -> "phone";
            case TIMESTAMP -> "timestamp";
            case BILLING_CITY -> "billing_city";
            case BILLING_COUNTRY -> "billing_country";
            case BILLING_POSTAL_CODE -> "billing_postal_code";
            case SHIPPING_CITY -> "shipping_city";
            case SHIPPING_COUNTRY -> "shipping_country";
            case SHIPPING_POSTAL_CODE -> "shipping_postal_code";
            case CARD_NETWORK -> "card_network";
            case CARD_BIN -> "card_bin";
            case CARD_LOGO -> "card_logo";
            default -> "UNKNOWN";
        };
    }

    /**
     * Checks if a field ID is valid (a standard field).
     * Field IDs start from 1, not 0.
     *
     * @param fieldId the field ID to check
     * @return true if the field ID is valid, false otherwise
     */
    public static boolean isValid(int fieldId) {
        return fieldId >= 1 && fieldId < FIELD_COUNT;
    }

    /**
     * Gets the total number of standard fields.
     *
     * @return the field count
     */
    public static int getFieldCount() {
        return FIELD_COUNT;
    }

    // Prevent instantiation
    private FieldRegistry() {
        throw new UnsupportedOperationException("Utility class");
    }
}
