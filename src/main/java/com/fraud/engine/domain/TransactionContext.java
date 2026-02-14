package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonIgnore;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * Represents a transaction to be evaluated by the rule engine.
 *
 * <p>Contains all the data fields that rules can evaluate against.
 * Standard fields are defined, but additional custom fields can be added.
 *
 * <p><b>Performance Optimization:</b> Fields are stored in an Object array for O(1)
 * direct access without HashMap overhead. The individual field properties are maintained
 * for Jackson deserialization compatibility and backward compatibility.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TransactionContext {

    // ========== Field ID Constants ==========
    // These constants provide zero-allocation field access via the array.
    // They reference the centralized FieldRegistry for single source of truth.

    /** Field ID for transaction_id */
    public static final int F_TRANSACTION_ID = FieldRegistry.TRANSACTION_ID;

    /** Field ID for card_hash */
    public static final int F_CARD_HASH = FieldRegistry.CARD_HASH;

    /** Field ID for amount */
    public static final int F_AMOUNT = FieldRegistry.AMOUNT;

    /** Field ID for currency */
    public static final int F_CURRENCY = FieldRegistry.CURRENCY;

    /** Field ID for merchant_id */
    public static final int F_MERCHANT_ID = FieldRegistry.MERCHANT_ID;

    /** Field ID for merchant_name */
    public static final int F_MERCHANT_NAME = FieldRegistry.MERCHANT_NAME;

    /** Field ID for merchant_category */
    public static final int F_MERCHANT_CATEGORY = FieldRegistry.MERCHANT_CATEGORY;

    /** Field ID for merchant_category_code */
    public static final int F_MERCHANT_CATEGORY_CODE = FieldRegistry.MERCHANT_CATEGORY_CODE;

    /** Field ID for card_present */
    public static final int F_CARD_PRESENT = FieldRegistry.CARD_PRESENT;

    /** Field ID for transaction_type */
    public static final int F_TRANSACTION_TYPE = FieldRegistry.TRANSACTION_TYPE;

    /** Field ID for entry_mode */
    public static final int F_ENTRY_MODE = FieldRegistry.ENTRY_MODE;

    /** Field ID for country_code */
    public static final int F_COUNTRY_CODE = FieldRegistry.COUNTRY_CODE;

    /** Field ID for ip_address */
    public static final int F_IP_ADDRESS = FieldRegistry.IP_ADDRESS;

    /** Field ID for device_id */
    public static final int F_DEVICE_ID = FieldRegistry.DEVICE_ID;

    /** Field ID for email */
    public static final int F_EMAIL = FieldRegistry.EMAIL;

    /** Field ID for phone */
    public static final int F_PHONE = FieldRegistry.PHONE;

    /** Field ID for timestamp */
    public static final int F_TIMESTAMP = FieldRegistry.TIMESTAMP;

    /** Field ID for billing_city */
    public static final int F_BILLING_CITY = FieldRegistry.BILLING_CITY;

    /** Field ID for billing_country */
    public static final int F_BILLING_COUNTRY = FieldRegistry.BILLING_COUNTRY;

    /** Field ID for billing_postal_code */
    public static final int F_BILLING_POSTAL_CODE = FieldRegistry.BILLING_POSTAL_CODE;

    /** Field ID for shipping_city */
    public static final int F_SHIPPING_CITY = FieldRegistry.SHIPPING_CITY;

    /** Field ID for shipping_country */
    public static final int F_SHIPPING_COUNTRY = FieldRegistry.SHIPPING_COUNTRY;

    /** Field ID for shipping_postal_code */
    public static final int F_SHIPPING_POSTAL_CODE = FieldRegistry.SHIPPING_POSTAL_CODE;

    /** Field ID for card_network (for scope-based routing) */
    public static final int F_CARD_NETWORK = FieldRegistry.CARD_NETWORK;

    /** Field ID for card_bin (for scope-based routing) */
    public static final int F_CARD_BIN = FieldRegistry.CARD_BIN;

    /** Field ID for card_logo (for scope-based routing) */
    public static final int F_CARD_LOGO = FieldRegistry.CARD_LOGO;

    /** Number of standard fields */
    public static final int F_COUNT = FieldRegistry.FIELD_COUNT;

    // ========== Properties (for Jackson deserialization) ==========

    @JsonProperty("transaction_id")
    private String transactionId;

    @JsonProperty("card_hash")
    private String cardHash;

    @JsonProperty("amount")
    private BigDecimal amount;

    @JsonProperty("currency")
    private String currency;

    @JsonProperty("merchant_id")
    private String merchantId;

    @JsonProperty("merchant_name")
    private String merchantName;

    @JsonProperty("merchant_category")
    private String merchantCategory;

    @JsonProperty("merchant_category_code")
    private String merchantCategoryCode;

    @JsonProperty("card_present")
    private Boolean cardPresent;

    @JsonProperty("transaction_type")
    private String transactionType;

    @JsonProperty("entry_mode")
    private String entryMode;

    @JsonProperty("country_code")
    private String countryCode;

    @JsonProperty("ip_address")
    private String ipAddress;

    @JsonProperty("device_id")
    private String deviceId;

    @JsonProperty("email")
    private String email;

    @JsonProperty("phone")
    private String phone;

    @JsonProperty("billing_address")
    private Address billingAddress;

    @JsonProperty("shipping_address")
    private Address shippingAddress;

    @JsonProperty("timestamp")
    private String timestampRaw;

    // Lazily parsed from timestampRaw only when getTimestamp() is called.
    private transient Instant timestamp;

    @JsonProperty("decision")
    private String decision;

    // Scope-related fields for rule bucketing
    @JsonProperty("card_network")
    private String cardNetwork;

    @JsonProperty("card_bin")
    private String cardBin;

    @JsonProperty("card_logo")
    private String cardLogo;

    @JsonProperty("custom_fields")
    private Map<String, Object> customFields;

    // ========== Fast Access Array ==========
    // Fixed-size array for O(1) field access without HashMap overhead.
    // This is indexed by the F_* constants above.
    // Transient means it won't be serialized by Jackson (we use properties instead).
    private transient Object[] fields;

    // ========== Constructor ==========

    public TransactionContext() {
        // Initialize array with fixed size
        this.fields = new Object[F_COUNT];
    }

    // ========== Fast Field Access ==========

    /**
     * Gets a field value by field ID (O(1) array access).
     * <p>This is the preferred method for high-performance rule evaluation.
     * Field IDs start from 1, so we subtract 1 for array indexing.
     *
     * @param fieldId the field ID (e.g., F_CARD_HASH, F_AMOUNT)
     * @return the field value, or null if not set
     */
    public Object getField(int fieldId) {
        if (fieldId >= 1 && fieldId < F_COUNT) {
            return fields[fieldId - 1];
        }
        return null;
    }

    /**
     * Sets a field value by field ID.
     * Field IDs start from 1, so we subtract 1 for array indexing.
     *
     * @param fieldId the field ID (e.g., F_CARD_HASH, F_AMOUNT)
     * @param value the value to set
     */
    public void setField(int fieldId, Object value) {
        if (fieldId >= 1 && fieldId < F_COUNT) {
            fields[fieldId - 1] = value;
        }
    }

    // ========== Getters/Setters (backed by array + properties) ==========

    public String getTransactionId() {
        return transactionId;
    }

    public void setTransactionId(String transactionId) {
        this.transactionId = transactionId;
        this.fields[F_TRANSACTION_ID - 1] =transactionId;
    }

    public String getCardHash() {
        return cardHash;
    }

    public void setCardHash(String cardHash) {
        this.cardHash = cardHash;
        this.fields[F_CARD_HASH - 1] =cardHash;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public void setAmount(BigDecimal amount) {
        this.amount = amount;
        this.fields[F_AMOUNT - 1] =amount;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
        this.fields[F_CURRENCY - 1] =currency;
    }

    public String getMerchantId() {
        return merchantId;
    }

    public void setMerchantId(String merchantId) {
        this.merchantId = merchantId;
        this.fields[F_MERCHANT_ID - 1] =merchantId;
    }

    public String getMerchantName() {
        return merchantName;
    }

    public void setMerchantName(String merchantName) {
        this.merchantName = merchantName;
        this.fields[F_MERCHANT_NAME - 1] =merchantName;
    }

    public String getMerchantCategory() {
        return merchantCategory;
    }

    public void setMerchantCategory(String merchantCategory) {
        this.merchantCategory = merchantCategory;
        this.fields[F_MERCHANT_CATEGORY - 1] =merchantCategory;
    }

    public String getMerchantCategoryCode() {
        return merchantCategoryCode;
    }

    public void setMerchantCategoryCode(String merchantCategoryCode) {
        this.merchantCategoryCode = merchantCategoryCode;
        this.fields[F_MERCHANT_CATEGORY_CODE - 1] =merchantCategoryCode;
    }

    public Boolean getCardPresent() {
        return cardPresent;
    }

    public void setCardPresent(Boolean cardPresent) {
        this.cardPresent = cardPresent;
        this.fields[F_CARD_PRESENT - 1] =cardPresent;
    }

    public String getTransactionType() {
        return transactionType;
    }

    public void setTransactionType(String transactionType) {
        this.transactionType = transactionType;
        this.fields[F_TRANSACTION_TYPE - 1] =transactionType;
    }

    public String getEntryMode() {
        return entryMode;
    }

    public void setEntryMode(String entryMode) {
        this.entryMode = entryMode;
        this.fields[F_ENTRY_MODE - 1] =entryMode;
    }

    public String getCountryCode() {
        return countryCode;
    }

    public void setCountryCode(String countryCode) {
        this.countryCode = countryCode;
        this.fields[F_COUNTRY_CODE - 1] =countryCode;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
        this.fields[F_IP_ADDRESS - 1] =ipAddress;
    }

    public String getDeviceId() {
        return deviceId;
    }

    public void setDeviceId(String deviceId) {
        this.deviceId = deviceId;
        this.fields[F_DEVICE_ID - 1] =deviceId;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
        this.fields[F_EMAIL - 1] =email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
        this.fields[F_PHONE - 1] = phone;
    }

    // ========== Scope Fields (for rule bucketing) ==========

    /**
     * Gets the card network (e.g., VISA, MASTERCARD, AMEX).
     * Used for scope-based rule bucketing.
     */
    public String getCardNetwork() {
        return cardNetwork;
    }

    public void setCardNetwork(String cardNetwork) {
        this.cardNetwork = cardNetwork;
        this.fields[F_CARD_NETWORK - 1] = cardNetwork;
    }

    /**
     * Gets the card BIN (Bank Identification Number).
     * Typically the first 6-8 digits of the card number.
     * Used for scope-based rule bucketing.
     */
    public String getCardBin() {
        return cardBin;
    }

    public void setCardBin(String cardBin) {
        this.cardBin = cardBin;
        this.fields[F_CARD_BIN - 1] =cardBin;
    }

    /**
     * Gets the card logo/brand.
     * Used for scope-based rule bucketing (especially for co-branded cards).
     */
    public String getCardLogo() {
        return cardLogo;
    }

    public void setCardLogo(String cardLogo) {
        this.cardLogo = cardLogo;
        this.fields[F_CARD_LOGO - 1] =cardLogo;
    }

    public Address getBillingAddress() {
        return billingAddress;
    }

    public void setBillingAddress(Address billingAddress) {
        this.billingAddress = billingAddress;
        // Extract address fields into array for fast access
        if (billingAddress != null) {
            this.fields[F_BILLING_CITY - 1] = billingAddress.getCity();
            this.fields[F_BILLING_COUNTRY - 1] = billingAddress.getCountry();
            this.fields[F_BILLING_POSTAL_CODE - 1] = billingAddress.getPostalCode();
        }
    }

    public Address getShippingAddress() {
        return shippingAddress;
    }

    public void setShippingAddress(Address shippingAddress) {
        this.shippingAddress = shippingAddress;
        // Extract address fields into array for fast access
        if (shippingAddress != null) {
            this.fields[F_SHIPPING_CITY - 1] = shippingAddress.getCity();
            this.fields[F_SHIPPING_COUNTRY - 1] = shippingAddress.getCountry();
            this.fields[F_SHIPPING_POSTAL_CODE - 1] = shippingAddress.getPostalCode();
        }
    }

    @JsonIgnore
    public Instant getTimestamp() {
        if (timestamp == null && timestampRaw != null) {
            timestamp = Instant.parse(timestampRaw);
        }
        return timestamp;
    }

    public void setTimestamp(Instant timestamp) {
        this.timestamp = timestamp;
        this.timestampRaw = timestamp != null ? timestamp.toString() : null;
        this.fields[F_TIMESTAMP - 1] = this.timestampRaw;
    }

    @JsonProperty("timestamp")
    public String getTimestampRaw() {
        return timestampRaw;
    }

    @JsonProperty("timestamp")
    public void setTimestampRaw(String timestampRaw) {
        this.timestampRaw = timestampRaw;
        this.timestamp = null;
        this.fields[F_TIMESTAMP - 1] = timestampRaw;
    }

    public String getDecision() {
        return decision;
    }

    public void setDecision(String decision) {
        this.decision = decision;
    }

    public Map<String, Object> getCustomFields() {
        if (customFields == null) {
            customFields = new HashMap<>();
        }
        return customFields;
    }

    /**
     * Returns custom fields without forcing allocation.
     * Intended for hot paths that only need to check whether custom fields exist.
     */
    public Map<String, Object> getCustomFieldsIfPresent() {
        return customFields;
    }

    public void setCustomFields(Map<String, Object> customFields) {
        this.customFields = customFields;
    }

    public void addCustomField(String key, Object value) {
        getCustomFields().put(key, value);
    }

    // ========== Context Projection ==========
    /**
     * Converts this transaction to a flat map for rule evaluation and downstream payloads.
     *
     * @return a map containing all populated field values
     */
    public Map<String, Object> toEvaluationContext() {
        Map<String, Object> context = new HashMap<>(32); // Pre-size to avoid resizing

        // Standard fields - field IDs start from 1, so we subtract 1 for array access
        if (fields[F_TRANSACTION_ID - 1] != null) context.put("transaction_id", fields[F_TRANSACTION_ID - 1]);
        if (fields[F_CARD_HASH - 1] != null) context.put("card_hash", fields[F_CARD_HASH - 1]);
        if (fields[F_AMOUNT - 1] != null) context.put("amount", fields[F_AMOUNT - 1]);
        if (fields[F_CURRENCY - 1] != null) context.put("currency", fields[F_CURRENCY - 1]);
        if (fields[F_MERCHANT_ID - 1] != null) context.put("merchant_id", fields[F_MERCHANT_ID - 1]);
        if (fields[F_MERCHANT_NAME - 1] != null) context.put("merchant_name", fields[F_MERCHANT_NAME - 1]);
        if (fields[F_MERCHANT_CATEGORY - 1] != null) context.put("merchant_category", fields[F_MERCHANT_CATEGORY - 1]);
        if (fields[F_MERCHANT_CATEGORY_CODE - 1] != null) context.put("merchant_category_code", fields[F_MERCHANT_CATEGORY_CODE - 1]);
        if (fields[F_CARD_PRESENT - 1] != null) context.put("card_present", fields[F_CARD_PRESENT - 1]);
        if (fields[F_TRANSACTION_TYPE - 1] != null) context.put("transaction_type", fields[F_TRANSACTION_TYPE - 1]);
        if (fields[F_ENTRY_MODE - 1] != null) context.put("entry_mode", fields[F_ENTRY_MODE - 1]);
        if (fields[F_COUNTRY_CODE - 1] != null) context.put("country_code", fields[F_COUNTRY_CODE - 1]);
        if (fields[F_IP_ADDRESS - 1] != null) context.put("ip_address", fields[F_IP_ADDRESS - 1]);
        if (fields[F_DEVICE_ID - 1] != null) context.put("device_id", fields[F_DEVICE_ID - 1]);
        if (fields[F_EMAIL - 1] != null) context.put("email", fields[F_EMAIL - 1]);
        if (fields[F_PHONE - 1] != null) context.put("phone", fields[F_PHONE - 1]);
        if (fields[F_TIMESTAMP - 1] != null) context.put("timestamp", fields[F_TIMESTAMP - 1]);
        if (fields[F_BILLING_CITY - 1] != null) context.put("billing_city", fields[F_BILLING_CITY - 1]);
        if (fields[F_BILLING_COUNTRY - 1] != null) context.put("billing_country", fields[F_BILLING_COUNTRY - 1]);
        if (fields[F_BILLING_POSTAL_CODE - 1] != null) context.put("billing_postal_code", fields[F_BILLING_POSTAL_CODE - 1]);
        if (fields[F_SHIPPING_CITY - 1] != null) context.put("shipping_city", fields[F_SHIPPING_CITY - 1]);
        if (fields[F_SHIPPING_COUNTRY - 1] != null) context.put("shipping_country", fields[F_SHIPPING_COUNTRY - 1]);
        if (fields[F_SHIPPING_POSTAL_CODE - 1] != null) context.put("shipping_postal_code", fields[F_SHIPPING_POSTAL_CODE - 1]);

        // Scope fields
        if (fields[F_CARD_NETWORK - 1] != null) context.put("card_network", fields[F_CARD_NETWORK - 1]);
        if (fields[F_CARD_BIN - 1] != null) context.put("card_bin", fields[F_CARD_BIN - 1]);
        if (fields[F_CARD_LOGO - 1] != null) context.put("card_logo", fields[F_CARD_LOGO - 1]);

        if (decision != null) context.put("decision", decision);

        // Custom fields
        if (customFields != null) {
            context.putAll(customFields);
        }

        return context;
    }

    public Map<String, Object> toMinimalContext() {
        Map<String, Object> context = new HashMap<>(8);
        if (fields[F_TRANSACTION_ID - 1] != null) context.put("transaction_id", fields[F_TRANSACTION_ID - 1]);
        if (fields[F_CARD_HASH - 1] != null) context.put("card_hash", fields[F_CARD_HASH - 1]);
        if (fields[F_AMOUNT - 1] != null) context.put("amount", fields[F_AMOUNT - 1]);
        if (fields[F_CURRENCY - 1] != null) context.put("currency", fields[F_CURRENCY - 1]);
        if (fields[F_MERCHANT_CATEGORY_CODE - 1] != null) context.put("merchant_category_code", fields[F_MERCHANT_CATEGORY_CODE - 1]);
        if (fields[F_COUNTRY_CODE - 1] != null) context.put("country_code", fields[F_COUNTRY_CODE - 1]);
        if (fields[F_CARD_NETWORK - 1] != null) context.put("card_network", fields[F_CARD_NETWORK - 1]);
        if (fields[F_CARD_BIN - 1] != null) context.put("card_bin", fields[F_CARD_BIN - 1]);
        if (fields[F_CARD_LOGO - 1] != null) context.put("card_logo", fields[F_CARD_LOGO - 1]);
        return context;
    }

    // ========== Address Class ==========

    /**
     * Address representation for billing/shipping.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Address {

        @JsonProperty("street1")
        private String street1;

        @JsonProperty("street2")
        private String street2;

        @JsonProperty("city")
        private String city;

        @JsonProperty("state")
        private String state;

        @JsonProperty("postal_code")
        private String postalCode;

        @JsonProperty("country")
        private String country;

        public String getStreet1() {
            return street1;
        }

        public void setStreet1(String street1) {
            this.street1 = street1;
        }

        public String getStreet2() {
            return street2;
        }

        public void setStreet2(String street2) {
            this.street2 = street2;
        }

        public String getCity() {
            return city;
        }

        public void setCity(String city) {
            this.city = city;
        }

        public String getState() {
            return state;
        }

        public void setState(String state) {
            this.state = state;
        }

        public String getPostalCode() {
            return postalCode;
        }

        public void setPostalCode(String postalCode) {
            this.postalCode = postalCode;
        }

        public String getCountry() {
            return country;
        }

        public void setCountry(String country) {
            this.country = country;
        }
    }
}
