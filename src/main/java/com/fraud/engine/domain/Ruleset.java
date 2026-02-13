package com.fraud.engine.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Represents a ruleset containing a collection of rules.
 *
 * A ruleset is identified by a key and version, and contains:
 * - Rules that will be evaluated
 * - Metadata (version, created timestamp, etc.)
 * - Evaluation mode (AUTH or MONITORING)
 * - Compiled rules for high-performance evaluation
 * - Scope buckets for efficient rule filtering
 */
public class Ruleset {
    private static final int APPLICABLE_RULE_CACHE_MAX_ENTRIES = 2048;

    @NotBlank(message = "Ruleset key is required")
    @JsonProperty("key")
    private String key;

    @NotNull(message = "Version is required")
    @JsonProperty("version")
    private Integer version;

    @JsonProperty("name")
    private String name;

    @JsonProperty("description")
    private String description;

    @JsonProperty("evaluation_type")
    private String evaluationType;

    @JsonProperty("rules")
    private List<Rule> rules = new ArrayList<>();

    private volatile List<Rule> cachedSortedRules;

    @JsonProperty("created_at")
    private Instant createdAt;

    @JsonProperty("created_by")
    private String createdBy;

    @JsonProperty("active")
    private boolean active = true;

    @JsonProperty("field_registry_version")
    private Integer fieldRegistryVersion;

    @JsonProperty("ruleset_id")
    private String rulesetId;

    private transient Map<String, List<Rule>> networkBuckets;
    private transient Map<String, List<Rule>> binBuckets;
    private transient Map<String, List<Rule>> mccBuckets;
    private transient Map<String, List<Rule>> logoBuckets;
    private transient List<Rule> globalRules;
    private transient volatile boolean scopeBucketsBuilt = false;
    private transient volatile ConcurrentHashMap<ScopeCacheKey, List<Rule>> applicableRulesCache;

    public Ruleset() {
    }

    public Ruleset(String key, Integer version) {
        this.key = key;
        this.version = version;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public Integer getVersion() {
        return version;
    }

    public void setVersion(Integer version) {
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getEvaluationType() {
        return evaluationType;
    }

    public void setEvaluationType(String evaluationType) {
        this.evaluationType = evaluationType;
    }

    public List<Rule> getRules() {
        return rules;
    }

    public void setRules(List<Rule> rules) {
        this.rules = rules != null ? new ArrayList<>(rules) : new ArrayList<>();
        invalidateCachedRules();
        this.scopeBucketsBuilt = false;
        this.applicableRulesCache = null;
    }

    public void addRule(Rule rule) {
        this.rules.add(rule);
        invalidateCachedRules();
        this.scopeBucketsBuilt = false;
        this.applicableRulesCache = null;
    }

    /**
     * Invalidates cached sorted rules.
     */
    public void invalidateCachedRules() {
        synchronized (this) {
            cachedSortedRules = null;
        }
        applicableRulesCache = null;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }

    /**
     * Gets the field registry version required by this ruleset.
     *
     * @return the field registry version, or null if not specified (legacy ruleset)
     */
    public Integer getFieldRegistryVersion() {
        return fieldRegistryVersion;
    }

    /**
     * Sets the field registry version required by this ruleset.
     *
     * @param fieldRegistryVersion the field registry version
     */
    public void setFieldRegistryVersion(Integer fieldRegistryVersion) {
        this.fieldRegistryVersion = fieldRegistryVersion;
    }

    public String getRulesetId() {
        return rulesetId;
    }

    public void setRulesetId(String rulesetId) {
        this.rulesetId = rulesetId;
    }

    /**
     * Builds scope buckets for efficient rule filtering.
     * Called automatically on first getApplicableRules() call.
     */
    private void buildScopeBuckets() {
        if (scopeBucketsBuilt) {
            return;
        }
        synchronized (this) {
            if (scopeBucketsBuilt) {
                return;
            }
            networkBuckets = new HashMap<>();
            binBuckets = new HashMap<>();
            mccBuckets = new HashMap<>();
            logoBuckets = new HashMap<>();
            globalRules = new ArrayList<>();
            applicableRulesCache = new ConcurrentHashMap<>();

            for (Rule rule : rules) {
                if (!rule.isEnabled()) {
                    continue;
                }
                RuleScope scope = rule.getScope();
                if (scope == null) {
                    globalRules.add(rule);
                    continue;
                }
                switch (scope.getType()) {
                    case NETWORK -> {
                        if (scope.getValue() != null) {
                            networkBuckets.computeIfAbsent(scope.getValue().toUpperCase(), k -> new ArrayList<>()).add(rule);
                        }
                        if (scope.getValues() != null) {
                            for (String val : scope.getValues()) {
                                networkBuckets.computeIfAbsent(val.toUpperCase(), k -> new ArrayList<>()).add(rule);
                            }
                        }
                    }
                    case BIN -> {
                        if (scope.getValue() != null) {
                            binBuckets.computeIfAbsent(scope.getValue(), k -> new ArrayList<>()).add(rule);
                        }
                        if (scope.getValues() != null) {
                            for (String val : scope.getValues()) {
                                binBuckets.computeIfAbsent(val, k -> new ArrayList<>()).add(rule);
                            }
                        }
                    }
                    case MCC -> {
                        if (scope.getValue() != null) {
                            mccBuckets.computeIfAbsent(scope.getValue(), k -> new ArrayList<>()).add(rule);
                        }
                        if (scope.getValues() != null) {
                            for (String val : scope.getValues()) {
                                mccBuckets.computeIfAbsent(val, k -> new ArrayList<>()).add(rule);
                            }
                        }
                    }
                    case LOGO -> {
                        if (scope.getValue() != null) {
                            logoBuckets.computeIfAbsent(scope.getValue().toUpperCase(), k -> new ArrayList<>()).add(rule);
                        }
                        if (scope.getValues() != null) {
                            for (String val : scope.getValues()) {
                                logoBuckets.computeIfAbsent(val.toUpperCase(), k -> new ArrayList<>()).add(rule);
                            }
                        }
                    }
                    case GLOBAL, COMBINED -> globalRules.add(rule);
                }
            }
            scopeBucketsBuilt = true;
        }
    }

    /**
     * Gets all rules applicable to the given scope dimensions.
     * Rules are returned in order of scope specificity (most specific first).
     *
     * @param network the card network (e.g., "VISA")
     * @param bin the card BIN (e.g., "411111")
     * @param mcc the merchant category code (e.g., "5411")
     * @param logo the card logo
     * @return list of applicable rules sorted by specificity
     */
    /**
     * ADR-0015: Scope bucket traversal comparator.
     * Order: scope specificity descending -> priority descending -> APPROVE-first tie-breaker.
     */
    private static final Comparator<Rule> SCOPE_TRAVERSAL_COMPARATOR =
            Comparator.comparingInt((Rule r) -> r.getScope() != null ? r.getScope().getSpecificity() : 0)
                    .reversed()
                    .thenComparing(Comparator.comparingInt(Rule::getPriority).reversed())
                    .thenComparing(r -> "APPROVE".equalsIgnoreCase(r.getAction()) ? 0 : 1);

    private record ScopeCacheKey(String network, String bin, String mcc, String logo) {
    }

    public List<Rule> getApplicableRules(String network, String bin, String mcc, String logo) {
        buildScopeBuckets();

        String normalizedNetwork = network != null ? network.toUpperCase() : null;
        String normalizedLogo = logo != null ? logo.toUpperCase() : null;
        ScopeCacheKey cacheKey = new ScopeCacheKey(normalizedNetwork, bin, mcc, normalizedLogo);

        ConcurrentHashMap<ScopeCacheKey, List<Rule>> cache = applicableRulesCache;
        if (cache != null) {
            List<Rule> cached = cache.get(cacheKey);
            if (cached != null) {
                return cached;
            }
        }

        List<Rule> computed = computeApplicableRules(normalizedNetwork, bin, mcc, normalizedLogo);

        if (cache != null) {
            if (cache.size() >= APPLICABLE_RULE_CACHE_MAX_ENTRIES) {
                cache.clear();
            }
            List<Rule> previous = cache.putIfAbsent(cacheKey, computed);
            if (previous != null) {
                return previous;
            }
        }

        return computed;
    }

    private List<Rule> computeApplicableRules(String normalizedNetwork, String bin, String mcc, String normalizedLogo) {
        List<Rule> applicable = new ArrayList<>(Math.max(8, globalRules != null ? globalRules.size() : 0));

        if (bin != null) {
            for (int len = bin.length(); len >= 1; len--) {
                String prefix = bin.substring(0, len);
                List<Rule> binRules = binBuckets.get(prefix);
                if (binRules != null) {
                    applicable.addAll(binRules);
                }
            }
        }

        if (mcc != null) {
            List<Rule> mccRules = mccBuckets.get(mcc);
            if (mccRules != null) {
                applicable.addAll(mccRules);
            }
        }

        if (normalizedNetwork != null) {
            List<Rule> networkRules = networkBuckets.get(normalizedNetwork);
            if (networkRules != null) {
                applicable.addAll(networkRules);
            }
        }

        if (normalizedLogo != null) {
            List<Rule> logoRules = logoBuckets.get(normalizedLogo);
            if (logoRules != null) {
                applicable.addAll(logoRules);
            }
        }

        if (globalRules != null) {
            applicable.addAll(globalRules);
        }

        // ADR-0015: Sort by scope specificity -> priority -> APPROVE-first
        applicable.sort(SCOPE_TRAVERSAL_COMPARATOR);
        return List.copyOf(applicable);
    }

    /**
     * Gets the count of rules in each scope bucket.
     *
     * @return map of scope type to rule count
     */
    public Map<String, Integer> getScopeBucketCounts() {
        buildScopeBuckets();
        Map<String, Integer> counts = new HashMap<>();
        counts.put("NETWORK", networkBuckets.values().stream().mapToInt(List::size).sum());
        counts.put("BIN", binBuckets.values().stream().mapToInt(List::size).sum());
        counts.put("MCC", mccBuckets.values().stream().mapToInt(List::size).sum());
        counts.put("LOGO", logoBuckets.values().stream().mapToInt(List::size).sum());
        counts.put("GLOBAL", globalRules.size());
        counts.put("TOTAL", rules.size());
        return counts;
    }

    /**
     * Checks if this ruleset is compatible with a given field registry version.
     *
     * @param registryVersion the field registry version
     * @return true if compatible (versions match), false otherwise
     */
    public boolean isCompatibleWith(int registryVersion) {
        if (fieldRegistryVersion == null) {
            // Legacy ruleset without field_registry_version - assume compatible
            return true;
        }
        return fieldRegistryVersion.equals(registryVersion);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Ruleset ruleset = (Ruleset) o;
        return Objects.equals(key, ruleset.key) &&
                Objects.equals(version, ruleset.version);
    }

    @Override
    public int hashCode() {
        return Objects.hash(key, version);
    }

    @Override
    public String toString() {
        return "Ruleset{" +
               "key='" + key + '\'' +
               ", version=v" + version +
               ", name='" + name + '\'' +
               ", evaluationType='" + evaluationType + '\'' +
               ", fieldRegistryVersion=" + fieldRegistryVersion +
               ", rulesCount=" + rules.size() +
               ", active=" + active +
               '}';
    }

    /**
     * Returns a unique identifier for this ruleset.
     */
    public String getFullKey() {
        return key + "/v" + version;
    }

    /**
     * Gets rules sorted by priority (highest first).
     * <p>
     * Performance: Sorting is cached after first call. Sorting only happens:
     * <ul>
     *   <li>At ruleset load time (if preSort() is called)</li>
     *   <li>At hot reload time</li>
     *   <li>On first evaluation if not pre-sorted</li>
     * </ul>
     * <p>
     * Uses double-checked locking for thread-safe lazy initialization.
     *
     * @return immutable list of rules sorted by priority (highest first)
     */
    public List<Rule> getRulesByPriority() {
        List<Rule> cached = cachedSortedRules;
        if (cached == null) {
            synchronized (this) {
                cached = cachedSortedRules;
                if (cached == null) {
                    // Sort once: highest priority first
                    cached = rules.stream()
                            .filter(Rule::isEnabled)
                            .sorted((r1, r2) -> Integer.compare(r2.getPriority(), r1.getPriority()))
                            .toList();
                    // Use unmodifiable list for safety and immutability
                    cachedSortedRules = cached;
                }
            }
        }
        return cached;
    }

    /**
     * Pre-sorts rules during loading.
     * <p>
     * Call this immediately after loading a ruleset to front-load the sorting cost.
     * This ensures the first evaluation doesn't incur the sorting overhead.
     * <p>
     * Recommended: Call in RulesetLoader after deserializing from YAML.
     */
    public void preSort() {
        getRulesByPriority(); // Triggers sorting and caching
    }
}
