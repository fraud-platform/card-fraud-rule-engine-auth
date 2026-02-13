package com.fraud.engine.ruleset;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fraud.engine.domain.Ruleset;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@ApplicationScoped
public class RulesetRegistry {

    private static final Logger LOG = Logger.getLogger(RulesetRegistry.class);

    private final ConcurrentHashMap<String, ConcurrentHashMap<String, Ruleset>> registry =
            new ConcurrentHashMap<>();

    @Inject
    RulesetLoader loader;

    @ConfigProperty(name = "app.ruleset.auto-reload.enabled", defaultValue = "false")
    boolean autoReloadEnabled;

    @ConfigProperty(name = "app.ruleset.auto-reload.interval-seconds", defaultValue = "60")
    int autoReloadIntervalSeconds;

    private ScheduledExecutorService reloadScheduler;

    @PostConstruct
    void init() {
        LOG.info("Initializing RulesetRegistry");

        if (autoReloadEnabled) {
            startReloadScheduler();
            LOG.infof("Auto-reload enabled: checking every %d seconds", autoReloadIntervalSeconds);
        } else {
            LOG.info("Auto-reload disabled (manual reload only)");
        }
    }

    @PreDestroy
    void destroy() {
        if (reloadScheduler != null) {
            reloadScheduler.shutdown();
            try {
                if (!reloadScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    reloadScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                reloadScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        LOG.info("RulesetRegistry destroyed");
    }

    // ========== Lookup Operations ==========

    /**
     * Gets a ruleset for the specified country and key.
     * <p>
     * This is a non-blocking read operation suitable for the hot path.
     *
     * @param country the country code (e.g., "US", "UK")
     * @param rulesetKey the ruleset key (e.g., "CARD_AUTH")
     * @return the compiled ruleset, or null if not found
     */
    public Ruleset getRuleset(String country, String rulesetKey) {
        ConcurrentHashMap<String, Ruleset> countryRulesets = registry.get(country);
        if (countryRulesets == null) {
            return null;
        }
        return countryRulesets.get(rulesetKey);
    }

    /**
     * Gets a ruleset without country isolation.
     * Uses a default "global" namespace.
     *
     * @param rulesetKey the ruleset key
     * @return the compiled ruleset, or null if not found
     */
    public Ruleset getRuleset(String rulesetKey) {
        return getRuleset("global", rulesetKey);
    }

    /**
     * Gets a ruleset with country-specific lookup and global fallback (ADR-0016).
     * <p>
     * Tries country-specific first, then falls back to global namespace.
     *
     * @param country the country code from the transaction
     * @param rulesetKey the ruleset key
     * @return the compiled ruleset, or null if not found in either namespace
     */
    public Ruleset getRulesetWithFallback(String country, String rulesetKey) {
        if (country != null && !country.isBlank() && !"global".equalsIgnoreCase(country)) {
            Ruleset countrySpecific = getRuleset(country.toUpperCase(), rulesetKey);
            if (countrySpecific != null) {
                return countrySpecific;
            }
        }
        return getRuleset("global", rulesetKey);
    }

    /**
     * Gets the latest version of a ruleset from the specified country.
     * Checks S3/MinIO for the latest version and loads it if not cached.
     * <p>
     * <b>WARNING:</b> This method performs S3 I/O and should NOT be called on the
     * hot path (request processing). Use {@link #getRuleset(String)} for hot path access.
     * <p>
     * This method is intended for startup loading only.
     *
     * @param country the country code (e.g., "global", "local")
     * @param rulesetKey the ruleset key
     * @return the compiled ruleset, or null if not found
     */
    public synchronized Ruleset getOrLoadLatest(String country, String rulesetKey) {
        // Check cache first
        Ruleset cached = getRuleset(country, rulesetKey);
        if (cached != null) {
            return cached;
        }

        // Load from S3 with country-partitioned path support
        return loader.loadLatestCompiledRuleset(country, rulesetKey)
                .map(compiled -> {
                    register(country, compiled);
                    return compiled;
                })
                .orElse(null);
    }

    /**
     * Gets the latest version of a ruleset from the global namespace.
     * Checks S3/MinIO for the latest version and loads it if not cached.
     * <p>
     * <b>WARNING:</b> This method performs S3 I/O and should NOT be called on the
     * hot path (request processing). Use {@link #getRuleset(String)} for hot path access.
     * <p>
     * This method is intended for startup loading only.
     *
     * @param rulesetKey the ruleset key
     * @return the compiled ruleset, or null if not found
     */
    public synchronized Ruleset getOrLoadLatest(String rulesetKey) {
        return getOrLoadLatest("global", rulesetKey);
    }

    // ========== Registration Operations ==========

    /**
     * Registers a compiled ruleset.
     * <p>
     * Thread-safe: Uses atomic ConcurrentHashMap operations.
     *
     * @param country the country code
     * @param compiled the compiled ruleset to register
     */
    public void register(String country, Ruleset compiled) {
        registry
                .computeIfAbsent(country, k -> new ConcurrentHashMap<>())
                .put(compiled.getKey(), compiled);

        LOG.infof("Registered ruleset: country=%s, key=%s, version=%d",
                country, compiled.getKey(), compiled.getVersion());
    }

    /**
     * Registers a compiled ruleset in the global namespace.
     *
     * @param compiled the compiled ruleset to register
     */
    public void register(Ruleset compiled) {
        register("global", compiled);
    }

    /**
     * Loads and registers a ruleset.
     * Used during initial startup.
     *
     * @param country the country code
     * @param rulesetKey the ruleset key
     * @param version the ruleset version
     * @return true if loading and registration succeeded
     */
    public boolean loadAndRegister(String country, String rulesetKey, int version) {
        try {
            Ruleset compiled = loader.loadCompiledRuleset(rulesetKey, version).orElse(null);
            if (compiled == null) {
                LOG.errorf("Failed to load ruleset: %s v%d", rulesetKey, version);
                return false;
            }

            register(country, compiled);
            LOG.infof("Loaded and registered: country=%s, key=%s, version=%d",
                    country, rulesetKey, version);
            return true;

        } catch (Exception e) {
            LOG.errorf(e, "Error loading ruleset: %s v%d", rulesetKey, version);
            return false;
        }
    }

    /**
     * Loads and registers a ruleset in the global namespace.
     *
     * @param rulesetKey the ruleset key
     * @param version the ruleset version
     * @return true if loading and registration succeeded
     */
    public boolean loadAndRegister(String rulesetKey, int version) {
        return loadAndRegister("global", rulesetKey, version);
    }

    /**
     * Bulk loads multiple rulesets at startup.
     *
     * @param rulesets list of ruleset specifications to load
     * @return count of successfully loaded rulesets
     */
    public int bulkLoad(List<RulesetSpec> rulesets) {
        LOG.infof("Bulk loading %d rulesets", rulesets.size());
        int successCount = 0;

        for (RulesetSpec spec : rulesets) {
            String country = spec.country != null ? spec.country : "global";
            if (loadAndRegister(country, spec.key, spec.version)) {
                successCount++;
            }
        }

        LOG.infof("Bulk load complete: %d/%d rulesets loaded", successCount, rulesets.size());
        return successCount;
    }

    // ========== Hot Swap Operations ==========

    /**
     * Hot-swaps a ruleset atomically.
     * <p>
     * Process:
     * <ol>
     *   <li>Load new ruleset (don't modify registry yet)</li>
     *   <li>Validate it</li>
     *   <li>Swap atomically (single map operation)</li>
     *   <li>If any step fails, keep old version</li>
     * </ol>
     *
     * @param country the country code
     * @param rulesetKey the ruleset key
     * @param newVersion the new version to load
     * @return HotSwapResult with outcome
     */
    public HotSwapResult hotSwap(String country, String rulesetKey, int newVersion) {
        LOG.infof("Hot swap requested: country=%s, key=%s, newVersion=%d",
                country, rulesetKey, newVersion);

        // Step 1: Load new ruleset (don't modify registry yet)
        Ruleset newRuleset;
        try {
            newRuleset = loader.loadCompiledRuleset(rulesetKey, newVersion).orElse(null);

            if (newRuleset == null) {
                LOG.errorf("Hot swap failed: could not load %s v%d", rulesetKey, newVersion);
                return new HotSwapResult(false, "LOAD_FAILED", "Could not load ruleset", -1);
            }

        } catch (Exception e) {
            LOG.errorf(e, "Hot swap failed: error loading %s v%d", rulesetKey, newVersion);
            return new HotSwapResult(false, "LOAD_ERROR", "Failed to load ruleset", -1);
        }

        // Step 2: Validate (basic sanity check)
        if (newRuleset.getRules().isEmpty()) {
            LOG.warnf("Hot swap failed: new ruleset has no rules: %s v%d", rulesetKey, newVersion);
            return new HotSwapResult(false, "VALIDATION_FAILED", "Ruleset has no rules", -1);
        }

        // Step 3: Atomic swap (single map operation)
        try {
            ConcurrentHashMap<String, Ruleset> countryRulesets =
                    registry.get(country);

            if (countryRulesets == null) {
                countryRulesets = new ConcurrentHashMap<>();
                ConcurrentHashMap<String, Ruleset> existing =
                        registry.putIfAbsent(country, countryRulesets);
                if (existing != null) {
                    countryRulesets = existing;
                }
            }

            // Get old version for logging
            Ruleset oldRuleset = countryRulesets.get(rulesetKey);
            int oldVersion = oldRuleset != null ? oldRuleset.getVersion() : -1;

            // Atomic replace
            countryRulesets.put(rulesetKey, newRuleset);

            LOG.infof("Hot swap successful: country=%s, key=%s, oldVersion=%d, newVersion=%d",
                    country, rulesetKey, oldVersion, newVersion);

            return new HotSwapResult(true, "SUCCESS", "Hot swap completed", oldVersion);

        } catch (Exception e) {
            LOG.errorf(e, "Hot swap failed: error during swap for %s v%d", rulesetKey, newVersion);
            return new HotSwapResult(false, "SWAP_ERROR", "Failed to swap ruleset", -1);
        }
    }

    /**
     * Hot-swaps a ruleset in the global namespace.
     *
     * @param rulesetKey the ruleset key
     * @param newVersion the new version to load
     * @return HotSwapResult with outcome
     */
    public HotSwapResult hotSwap(String rulesetKey, int newVersion) {
        return hotSwap("global", rulesetKey, newVersion);
    }

    // ========== Management Operations ==========

    /**
     * Gets all countries in registry.
     *
     * @return set of country codes
     */
    public Set<String> getCountries() {
        return Set.copyOf(registry.keySet());
    }

    /**
     * Gets all ruleset keys for a country.
     *
     * @param country the country code
     * @return set of ruleset keys
     */
    public Set<String> getRulesetKeys(String country) {
        ConcurrentHashMap<String, Ruleset> countryRulesets = registry.get(country);
        return countryRulesets != null ? Set.copyOf(countryRulesets.keySet()) : Set.of();
    }

    /**
     * Gets the total number of rulesets cached.
     *
     * @return total count
     */
    public int size() {
        return registry.values().stream()
                .mapToInt(Map::size)
                .sum();
    }

    /**
     * Clears all cached rulesets.
     */
    public void clear() {
        registry.clear();
        LOG.info("RulesetRegistry cleared");
    }

    /**
     * Clears rulesets for a specific country.
     *
     * @param country the country code
     */
    public void clearCountry(String country) {
        registry.remove(country);
        LOG.infof("Cleared rulesets for country: %s", country);
    }

    /**
     * Invalidates a specific ruleset (removes from cache).
     *
     * @param country the country code
     * @param rulesetKey the ruleset key
     * @return true if the ruleset was removed
     */
    public boolean invalidate(String country, String rulesetKey) {
        ConcurrentHashMap<String, Ruleset> countryRulesets = registry.get(country);
        if (countryRulesets == null) {
            return false;
        }
        boolean removed = countryRulesets.remove(rulesetKey) != null;
        if (removed) {
            LOG.infof("Invalidated ruleset: country=%s, key=%s", country, rulesetKey);
        }
        return removed;
    }

    // ========== Background Reload ==========

    private void startReloadScheduler() {
        reloadScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "ruleset-reload-scheduler");
            thread.setDaemon(true);
            return thread;
        });

        reloadScheduler.scheduleAtFixedRate(
                this::checkForUpdates,
                autoReloadIntervalSeconds,
                autoReloadIntervalSeconds,
                TimeUnit.SECONDS
        );
    }

    private void checkForUpdates() {
        try {
            LOG.debug("Checking for ruleset updates...");
            AtomicInteger updateCount = new AtomicInteger(0);

            for (Map.Entry<String, ConcurrentHashMap<String, Ruleset>> countryEntry : registry.entrySet()) {
                String country = countryEntry.getKey();
                for (Map.Entry<String, Ruleset> entry : countryEntry.getValue().entrySet()) {
                    String key = entry.getKey();
                    int currentVersion = entry.getValue().getVersion();

                    // Check if there's a newer version
                    loader.loadLatestCompiledRuleset(key).ifPresent(latest -> {
                        if (latest.getVersion() > currentVersion) {
                            LOG.infof("New version available: %s v%d (current: v%d)",
                                    key, latest.getVersion(), currentVersion);
                            HotSwapResult result = hotSwap(country, key, latest.getVersion());
                            if (result.success()) {
                                updateCount.incrementAndGet();
                            }
                        }
                    });
                }
            }

            int count = updateCount.get();
            if (count > 0) {
                LOG.infof("Auto-reload complete: %d rulesets updated", count);
            }

        } catch (Exception e) {
            LOG.errorf(e, "Error during auto-reload check");
        }
    }

    // ========== Inner Classes ==========

    /**
     * Specification for a ruleset to load.
     */
    public static class RulesetSpec {
        public final String key;
        public final int version;
        public final String country;

        public RulesetSpec(String key, int version) {
            this(key, version, null);
        }

        @JsonCreator
        public RulesetSpec(@JsonProperty("key") String key,
                           @JsonProperty("version") int version,
                           @JsonProperty("country") String country) {
            this.key = key;
            this.version = version;
            this.country = country;
        }

        public static RulesetSpec of(String key, int version) {
            return new RulesetSpec(key, version);
        }

        public static RulesetSpec of(String key, int version, String country) {
            return new RulesetSpec(key, version, country);
        }
    }

    /**
     * Result of a hot-swap operation.
     */
    public static class HotSwapResult {
        private final boolean success;
        private final String status;
        private final String message;
        private final int oldVersion;

        public HotSwapResult(boolean success, String status, String message, int oldVersion) {
            this.success = success;
            this.status = status;
            this.message = message;
            this.oldVersion = oldVersion;
        }

        public boolean success() {
            return success;
        }

        public String status() {
            return status;
        }

        public String message() {
            return message;
        }

        public int oldVersion() {
            return oldVersion;
        }

        @Override
        public String toString() {
            return "HotSwapResult{" +
                    "success=" + success +
                    ", status='" + status + '\'' +
                    ", message='" + message + '\'' +
                    ", oldVersion=" + oldVersion +
                    '}';
        }
    }
}
