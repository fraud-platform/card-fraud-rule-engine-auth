package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Represents the scope of a rule for efficient rule bucketing.
 * <p>
 * Scope-based routing allows the rule engine to quickly filter down to only
 * the rules that are applicable to a given transaction, significantly reducing
 * evaluation time for large rulesets.
 * <p>
 * Scope dimensions (in order of specificity):
 * <ol>
 *   <li><b>Network</b> - Card network (VISA, MASTERCARD, AMEX, DISCOVER, etc.)</li>
 *   <li><b>BIN</b> - Bank Identification Number (first 6-8 digits of card)</li>
 *   <li><b>MCC</b> - Merchant Category Code</li>
 *   <li><b>Logo</b> - Card brand/logo (for co-branded cards)</li>
 * </ol>
 * <p>
 * Rules with more specific scopes are evaluated before less specific ones.
 * A rule with no scope (GLOBAL) applies to all transactions.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class RuleScope {

    /**
     * Scope type enum defining the available scope dimensions.
     */
    public enum Type {
        /** Global scope - applies to all transactions */
        GLOBAL(0),
        /** Network scope - matches card network (VISA, MASTERCARD, etc.) */
        NETWORK(1),
        /** BIN scope - matches Bank Identification Number prefix */
        BIN(2),
        /** MCC scope - matches Merchant Category Code */
        MCC(3),
        /** Logo scope - matches card brand/logo */
        LOGO(4),
        /** Combined scope - multiple dimensions */
        COMBINED(5);

        private final int specificity;

        Type(int specificity) {
            this.specificity = specificity;
        }

        /**
         * Gets the specificity level for this scope type.
         * Higher values = more specific = evaluated first.
         */
        public int getSpecificity() {
            return specificity;
        }
    }

    /** Global scope singleton - applies to all transactions */
    public static final RuleScope GLOBAL = new RuleScope(Type.GLOBAL, null, null, null);

    private final Type type;
    private final String value;
    private final Set<String> values; // For multi-value scopes
    private final Map<String, Set<String>> dimensions; // For combined scopes

    // Cached hash code for performance
    private final int hashCode;

    /**
     * Creates a new rule scope with a single value.
     *
     * @param type the scope type
     * @param value the scope value (e.g., "VISA", "411111", "5411")
     */
    public RuleScope(Type type, String value) {
        this(type, value, null, null);
    }

    /**
     * Creates a new rule scope with multiple values.
     *
     * @param type the scope type
     * @param values the scope values (e.g., ["VISA", "MASTERCARD"])
     */
    public RuleScope(Type type, Set<String> values) {
        this(type, null, values, null);
    }

    @JsonCreator
    private RuleScope(
            @JsonProperty("type") Type type,
            @JsonProperty("value") String value,
            @JsonProperty("values") Set<String> values,
            @JsonProperty("dimensions") Map<String, Set<String>> dimensions) {
        this.type = type != null ? type : Type.GLOBAL;
        this.value = value;
        this.values = values != null ? Set.copyOf(values) : null;
        this.dimensions = dimensions != null ? Map.copyOf(dimensions) : null;
        this.hashCode = computeHashCode();
    }

    // ========== Factory Methods ==========

    /**
     * Creates a network scope.
     *
     * @param network the card network (e.g., "VISA", "MASTERCARD")
     * @return the network scope
     */
    public static RuleScope network(String network) {
        return new RuleScope(Type.NETWORK, network);
    }

    /**
     * Creates a BIN scope.
     *
     * @param bin the BIN prefix (e.g., "411111")
     * @return the BIN scope
     */
    public static RuleScope bin(String bin) {
        return new RuleScope(Type.BIN, bin);
    }

    /**
     * Creates an MCC scope.
     *
     * @param mcc the merchant category code (e.g., "5411")
     * @return the MCC scope
     */
    public static RuleScope mcc(String mcc) {
        return new RuleScope(Type.MCC, mcc);
    }

    /**
     * Creates a logo scope.
     *
     * @param logo the card logo/brand
     * @return the logo scope
     */
    public static RuleScope logo(String logo) {
        return new RuleScope(Type.LOGO, logo);
    }

    /**
     * Creates a multi-network scope.
     *
     * @param networks the card networks
     * @return the network scope
     */
    public static RuleScope networks(Set<String> networks) {
        return new RuleScope(Type.NETWORK, networks);
    }

    /**
     * Creates a multi-MCC scope.
     *
     * @param mccs the merchant category codes
     * @return the MCC scope
     */
    public static RuleScope mccs(Set<String> mccs) {
        return new RuleScope(Type.MCC, mccs);
    }

    /**
     * Creates a combined scope from multiple dimensions.
     *
     * @param dimensions map of dimension to allowed values
     * @return combined scope
     */
    public static RuleScope combined(Map<String, Set<String>> dimensions) {
        return new RuleScope(Type.COMBINED, null, null, dimensions);
    }

    /**
     * Parses a scope object from JSON node.
     *
     * @param scopeNode the scope JSON object
     * @param mapper object mapper for value conversion
     * @return a RuleScope or null if invalid
     */
    public static RuleScope fromScopeNode(JsonNode scopeNode, ObjectMapper mapper) {
        if (scopeNode == null || scopeNode.isNull() || scopeNode.isEmpty()) {
            return RuleScope.GLOBAL;
        }

        Map<String, Set<String>> dims = new LinkedHashMap<>();
        addScopeValues(dims, scopeNode, "network");
        addScopeValues(dims, scopeNode, "bin");
        addScopeValues(dims, scopeNode, "mcc");
        addScopeValues(dims, scopeNode, "logo");

        if (dims.isEmpty()) {
            return RuleScope.GLOBAL;
        }

        if (dims.size() == 1) {
            Map.Entry<String, Set<String>> entry = dims.entrySet().iterator().next();
            String key = entry.getKey();
            Set<String> values = entry.getValue();
            if ("network".equals(key)) {
                return values.size() == 1 ? RuleScope.network(values.iterator().next()) : new RuleScope(Type.NETWORK, values);
            }
            if ("bin".equals(key)) {
                return values.size() == 1 ? RuleScope.bin(values.iterator().next()) : new RuleScope(Type.BIN, values);
            }
            if ("mcc".equals(key)) {
                return values.size() == 1 ? RuleScope.mcc(values.iterator().next()) : RuleScope.mccs(values);
            }
            if ("logo".equals(key)) {
                return values.size() == 1 ? RuleScope.logo(values.iterator().next()) : new RuleScope(Type.LOGO, values);
            }
        }

        return RuleScope.combined(dims);
    }

    private static void addScopeValues(Map<String, Set<String>> dims, JsonNode scopeNode, String key) {
        JsonNode node = scopeNode.get(key);
        if (node == null || node.isNull()) {
            return;
        }
        Set<String> values = new HashSet<>();
        if (node.isArray()) {
            for (JsonNode item : node) {
                if (item.isTextual()) {
                    values.add(item.asText());
                }
            }
        } else if (node.isTextual()) {
            values.add(node.asText());
        }
        if (!values.isEmpty()) {
            dims.put(key, Set.copyOf(values));
        }
    }

    // ========== Matching ==========

    /**
     * Checks if this scope matches the given transaction attributes.
     *
     * @param network the transaction's card network
     * @param bin the transaction's BIN
     * @param mcc the transaction's MCC
     * @param logo the transaction's card logo
     * @return true if this scope matches the transaction
     */
    public boolean matches(String network, String bin, String mcc, String logo) {
        return switch (type) {
            case GLOBAL -> true;
            case NETWORK -> matchesValue(network);
            case BIN -> matchesBin(bin);
            case MCC -> matchesValue(mcc);
            case LOGO -> matchesValue(logo);
            case COMBINED -> matchesCombined(network, bin, mcc, logo);
        };
    }

    /**
     * Checks if the scope value matches the given value.
     */
    private boolean matchesValue(String transactionValue) {
        if (transactionValue == null) {
            return false;
        }
        if (value != null) {
            return value.equalsIgnoreCase(transactionValue);
        }
        if (values != null) {
            for (String v : values) {
                if (v.equalsIgnoreCase(transactionValue)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks if the BIN matches (prefix matching).
     */
    private boolean matchesBin(String transactionBin) {
        if (transactionBin == null) {
            return false;
        }
        if (value != null) {
            return transactionBin.startsWith(value);
        }
        if (values != null) {
            for (String prefix : values) {
                if (transactionBin.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Checks combined scope matching (all dimensions must match).
     */
    private boolean matchesCombined(String network, String bin, String mcc, String logo) {
        if (dimensions == null || dimensions.isEmpty()) {
            return true;
        }

        for (Map.Entry<String, Set<String>> entry : dimensions.entrySet()) {
            String key = entry.getKey();
            Set<String> values = entry.getValue();
            boolean match = switch (key) {
                case "network" -> matchesValueSet(network, values);
                case "bin" -> matchesBinSet(bin, values);
                case "mcc" -> matchesValueSet(mcc, values);
                case "logo" -> matchesValueSet(logo, values);
                default -> false;
            };
            if (!match) {
                return false;
            }
        }
        return true;
    }

    private boolean matchesValueSet(String transactionValue, Set<String> allowedValues) {
        if (transactionValue == null || allowedValues == null || allowedValues.isEmpty()) {
            return false;
        }
        for (String v : allowedValues) {
            if (v.equalsIgnoreCase(transactionValue)) {
                return true;
            }
        }
        return false;
    }

    private boolean matchesBinSet(String transactionBin, Set<String> allowedValues) {
        if (transactionBin == null || allowedValues == null || allowedValues.isEmpty()) {
            return false;
        }
        for (String prefix : allowedValues) {
            if (transactionBin.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // ========== Getters ==========

    public Type getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public Set<String> getValues() {
        return values;
    }

    public Map<String, Set<String>> getDimensions() {
        return dimensions;
    }

    /**
     * Gets the specificity level of this scope.
     * Higher values = more specific.
     */
    public int getSpecificity() {
        int base = type.getSpecificity();
        // BIN length adds to specificity (longer BIN = more specific)
        if (type == Type.BIN && value != null) {
            base += value.length();
        }
        if (type == Type.COMBINED && dimensions != null) {
            base += dimensions.size();
        }
        return base;
    }

    /**
     * Checks if this is a global scope.
     */
    public boolean isGlobal() {
        return type == Type.GLOBAL;
    }

    // ========== Object Methods ==========

    private int computeHashCode() {
        return Objects.hash(type, value, values, dimensions);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RuleScope ruleScope = (RuleScope) o;
        return type == ruleScope.type &&
                Objects.equals(value, ruleScope.value) &&
                Objects.equals(values, ruleScope.values) &&
                Objects.equals(dimensions, ruleScope.dimensions);
    }

    @Override
    public int hashCode() {
        return hashCode;
    }

    @Override
    public String toString() {
        if (type == Type.GLOBAL) {
            return "GLOBAL";
        }
        if (value != null) {
            return type.name() + ":" + value;
        }
        if (values != null) {
            return type.name() + ":" + values;
        }
        if (dimensions != null) {
            return type.name() + ":" + dimensions;
        }
        return type.name();
    }
}
