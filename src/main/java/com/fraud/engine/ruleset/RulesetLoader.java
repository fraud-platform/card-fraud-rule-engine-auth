package com.fraud.engine.ruleset;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fraud.engine.dto.RulesetManifest;
import com.fraud.engine.domain.Condition;
import com.fraud.engine.domain.CompiledCondition;
import com.fraud.engine.domain.Rule;
import com.fraud.engine.domain.RuleScope;
import com.fraud.engine.domain.Ruleset;
import com.fraud.engine.domain.VelocityConfig;
import com.fraud.engine.engine.ConditionCompiler;
import com.fraud.engine.util.DecisionNormalizer;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for loading rulesets from MinIO/S3 storage.
 *
 * Production runtime uses manifest.json pointers to immutable ruleset.json artifacts.
 * YAML loading is supported only for local dev testing when explicitly enabled.
 */
@ApplicationScoped
public class RulesetLoader {

    private static final Logger LOG = Logger.getLogger(RulesetLoader.class);

    @ConfigProperty(name = "s3.endpoint-url")
    String endpointUrl;

    @ConfigProperty(name = "s3.aws.region")
    String region;

    @ConfigProperty(name = "s3.aws.credentials.static-provider.access-key-id")
    String accessKeyId;

    @ConfigProperty(name = "s3.aws.credentials.static-provider.secret-access-key")
    String secretAccessKey;

    @ConfigProperty(name = "app.ruleset.bucket", defaultValue = "fraud-gov-artifacts")
    String bucketName;

    @ConfigProperty(name = "app.ruleset.path-prefix", defaultValue = "rulesets/")
    String pathPrefix;

    @ConfigProperty(name = "app.ruleset.environment", defaultValue = "local")
    String rulesetEnvironment;

    @ConfigProperty(name = "app.ruleset.yaml-fallback-enabled", defaultValue = "false")
    boolean yamlFallbackEnabled;

    private S3Client s3Client;
    private final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());
    private final ObjectMapper jsonMapper = new ObjectMapper();
    private final Map<String, Ruleset> rulesetCache = new ConcurrentHashMap<>();

    @PostConstruct
    void init() {
        try {
            // Configure Jackson ObjectMapper to handle Java 8 date/time types
            jsonMapper.registerModule(new JavaTimeModule());
            jsonMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

            LOG.infof("Initializing S3 client for MinIO: %s", endpointUrl);

            s3Client = S3Client.builder()
                    .endpointOverride(URI.create(endpointUrl))
                    .region(Region.of(region))
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                    .forcePathStyle(true) // Required for MinIO
                    .build();

            LOG.info("S3 client initialized successfully");

        } catch (Exception e) {
            LOG.error("Failed to initialize S3 client", e);
        }
    }

    /**
     * Loads the runtime manifest.json for a ruleset key with country-partitioned path support.
     * <p>
     * Tries country-partitioned path first: rulesets/{env}/{country}/{rulesetKey}/manifest.json
     * Falls back to legacy path if not found: rulesets/{env}/{rulesetKey}/manifest.json
     *
     * @param country the country code (e.g., "US")
     * @param rulesetKey the ruleset key (e.g., "CARD_AUTH")
     * @return manifest or null if not found
     */
    public RulesetManifest loadManifest(String country, String rulesetKey) {
        // Try country-partitioned path first
        try {
            String objectKey = buildRulesetPrefix(country, rulesetKey) + "manifest.json";

            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(request)) {
                return jsonMapper.readValue(inputStream, RulesetManifest.class);
            }

        } catch (NoSuchKeyException e) {
            LOG.debugf("Country-partitioned manifest not found, trying fallback: country=%s, key=%s", country, rulesetKey);
        } catch (Exception e) {
            LOG.warnf("Error loading country-partitioned manifest for %s/%s: %s", country, rulesetKey, e.getMessage());
        }

        // Fallback to legacy path (no country in path)
        try {
            String objectKey = buildRulesetPrefix(rulesetKey) + "manifest.json";

            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(request)) {
                RulesetManifest manifest = jsonMapper.readValue(inputStream, RulesetManifest.class);
                LOG.warnf("Using legacy manifest path for %s (migration to country-partitioned paths recommended)", rulesetKey);
                return manifest;
            }

        } catch (NoSuchKeyException e) {
            LOG.debugf("Ruleset manifest not found (tried both country and legacy paths): country=%s, key=%s", country, rulesetKey);
            return null;
        } catch (Exception e) {
            LOG.warnf("Failed to load ruleset manifest for %s: %s", rulesetKey, e.getMessage());
            return null;
        }
    }

    /**
     * Loads the runtime manifest.json for a ruleset key (legacy method for backward compatibility).
     * <p>
     * Uses legacy path: rulesets/{env}/{rulesetKey}/manifest.json
     * <p>
     * For new code, prefer {@link #loadManifest(String, String)} with explicit country parameter.
     *
     * @param rulesetKey the ruleset key (e.g., "CARD_AUTH")
     * @return manifest or null if not found
     */
    public RulesetManifest loadManifest(String rulesetKey) {
        try {
            String objectKey = buildRulesetPrefix(rulesetKey) + "manifest.json";

            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(request)) {
                return jsonMapper.readValue(inputStream, RulesetManifest.class);
            }

        } catch (NoSuchKeyException e) {
            LOG.debugf("Ruleset manifest not found: %s", rulesetKey);
            return null;
        } catch (Exception e) {
            LOG.warnf("Failed to load ruleset manifest for %s: %s", rulesetKey, e.getMessage());
            return null;
        }
    }

    /**
     * Loads the latest compiled ruleset via manifest.json with country-partitioned path support.
     * <p>
     * Tries country-partitioned paths first, falls back to legacy paths if not found.
     *
     * @param country the country code
     * @param rulesetKey the ruleset key
     * @return compiled ruleset or empty if not found
     */
    public Optional<Ruleset> loadLatestCompiledRuleset(String country, String rulesetKey) {
        RulesetManifest manifest = loadManifest(country, rulesetKey);
        if (manifest == null || manifest.getArtifactUri() == null) {
            LOG.warnf("Ruleset manifest missing or invalid for country=%s, key=%s", country, rulesetKey);
            return Optional.empty();
        }

        try {
            byte[] artifact = loadArtifactBytes(manifest.getArtifactUri());
            if (artifact == null || artifact.length == 0) {
                LOG.warnf("Ruleset artifact is empty for country=%s, key=%s", country, rulesetKey);
                return Optional.empty();
            }

            if (!verifyChecksum(artifact, manifest.getChecksum())) {
                LOG.errorf("Checksum mismatch for ruleset country=%s, key=%s (version %s)",
                        country, rulesetKey, manifest.getRulesetVersion());
                return Optional.empty();
            }

            Ruleset ruleset = parseRuleset(artifact, rulesetKey, manifest.getRulesetVersion());
            return Optional.of(ruleset);

        } catch (Exception e) {
            LOG.errorf(e, "Failed to load compiled ruleset for country=%s, key=%s", country, rulesetKey);
            return Optional.empty();
        }
    }

    /**
     * Loads the latest compiled ruleset via manifest.json (legacy method for backward compatibility).
     * <p>
     * Uses legacy path: rulesets/{env}/{rulesetKey}/
     * <p>
     * For new code, prefer {@link #loadLatestCompiledRuleset(String, String)} with explicit country parameter.
     *
     * @param rulesetKey the ruleset key
     * @return compiled ruleset or empty if not found
     */
    public Optional<Ruleset> loadLatestCompiledRuleset(String rulesetKey) {
        RulesetManifest manifest = loadManifest(rulesetKey);
        if (manifest == null || manifest.getArtifactUri() == null) {
            LOG.warnf("Ruleset manifest missing or invalid for key: %s", rulesetKey);
            return Optional.empty();
        }

        try {
            byte[] artifact = loadArtifactBytes(manifest.getArtifactUri());
            if (artifact == null || artifact.length == 0) {
                LOG.warnf("Ruleset artifact is empty for key: %s", rulesetKey);
                return Optional.empty();
            }

            if (!verifyChecksum(artifact, manifest.getChecksum())) {
                LOG.errorf("Checksum mismatch for ruleset %s (version %s)",
                        rulesetKey, manifest.getRulesetVersion());
                return Optional.empty();
            }

            Ruleset ruleset = parseRuleset(artifact, rulesetKey, manifest.getRulesetVersion());
            return Optional.of(ruleset);

        } catch (Exception e) {
            LOG.errorf(e, "Failed to load compiled ruleset for %s", rulesetKey);
            return Optional.empty();
        }
    }

    /**
     * Loads a specific compiled ruleset version (direct artifact path).
     *
     * @param rulesetKey the ruleset key
     * @param version the ruleset version
     * @return compiled ruleset or empty if not found
     */
    public Optional<Ruleset> loadCompiledRuleset(String rulesetKey, int version) {
        try {
            String objectKey = buildRulesetPrefix(rulesetKey) + "v" + version + "/ruleset.json";
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(request)) {
                byte[] artifact = inputStream.readAllBytes();
                if (artifact.length == 0) {
                    LOG.warnf("Ruleset artifact is empty: %s/v%d", rulesetKey, version);
                    return Optional.empty();
                }
                Ruleset ruleset = parseRuleset(artifact, rulesetKey, version);
                return Optional.of(ruleset);
            }

        } catch (NoSuchKeyException e) {
            LOG.warnf("Ruleset not found: %s/v%d", rulesetKey, version);
            return Optional.empty();
        } catch (Exception e) {
            LOG.errorf(e, "Error loading ruleset: %s/v%d", rulesetKey, version);
            return Optional.empty();
        }
    }

    /**
     * Checks if manifest.json is available for the ruleset.
     */
    public boolean isManifestAvailable(String rulesetKey) {
        return loadManifest(rulesetKey) != null;
    }

    /**
     * Loads a ruleset from S3 storage.
     *
     * @param rulesetKey the ruleset key (e.g., "CARD_AUTH")
     * @param version    the ruleset version
     * @return the loaded ruleset, or empty if not found
     */
    public Optional<Ruleset> loadRuleset(String rulesetKey, int version) {
        if (!yamlFallbackEnabled) {
            LOG.warnf("YAML ruleset loading is disabled (rulesetKey=%s, version=%d)", rulesetKey, version);
            return Optional.empty();
        }

        String cacheKey = rulesetKey + "/v" + version;

        // Check cache first
        Ruleset cached = rulesetCache.get(cacheKey);
        if (cached != null) {
            LOG.debugf("Ruleset %s found in cache", cacheKey);
            return Optional.of(cached);
        }

        try {
            String objectKey = buildRulesetPrefix(rulesetKey) + "v" + version + "/ruleset.yaml";

            LOG.infof("Loading ruleset from S3: bucket=%s, key=%s", bucketName, objectKey);

            GetObjectRequest getObjectRequest = GetObjectRequest.builder()
                    .bucket(bucketName)
                    .key(objectKey)
                    .build();

            try (InputStream inputStream = s3Client.getObject(getObjectRequest)) {
                Ruleset ruleset = yamlMapper.readValue(inputStream, Ruleset.class);
                ruleset.setKey(rulesetKey);
                ruleset.setVersion(version);

                // Pre-sort rules at load time (not at evaluation time)
                // This front-loads the sorting cost and ensures first evaluation is fast
                ruleset.preSort();

                // Cache the ruleset (sorting is already cached in the ruleset)
                rulesetCache.put(cacheKey, ruleset);

                LOG.infof("Ruleset %s loaded successfully with %d rules (sorted and cached)",
                        cacheKey, ruleset.getRules().size());

                return Optional.of(ruleset);
            }

        } catch (NoSuchKeyException e) {
            LOG.warnf("Ruleset not found: %s/v%d", rulesetKey, version);
            return Optional.empty();

        } catch (Exception e) {
            LOG.errorf(e, "Error loading ruleset: %s/v%d", rulesetKey, version);
            return Optional.empty();
        }
    }

    /**
     * Loads the latest version of a ruleset.
     *
     * @param rulesetKey the ruleset key
     * @return the latest ruleset, or empty if not found
     */
    public Optional<Ruleset> loadLatestRuleset(String rulesetKey) {
        if (!yamlFallbackEnabled) {
            LOG.warnf("YAML ruleset loading is disabled (rulesetKey=%s)", rulesetKey);
            return Optional.empty();
        }

        try {
            // List versions to find the latest
            String prefix = buildRulesetPrefix(rulesetKey) + "v";

            ListObjectsV2Request listRequest = ListObjectsV2Request.builder()
                    .bucket(bucketName)
                    .prefix(prefix)
                    .build();

            int latestVersion = 0;
            for (S3Object s3Object : s3Client.listObjectsV2(listRequest).contents()) {
                String key = s3Object.key();
                // Extract version from path like "rulesets/CARD_AUTH/v3/ruleset.yaml"
                String versionStr = extractVersion(key);
                if (versionStr != null) {
                    try {
                        int version = Integer.parseInt(versionStr);
                        if (version > latestVersion) {
                            latestVersion = version;
                        }
                    } catch (NumberFormatException e) {
                        LOG.debugf("Could not parse version from: %s", key);
                    }
                }
            }

            if (latestVersion > 0) {
                return loadRuleset(rulesetKey, latestVersion);
            }

            LOG.warnf("No versions found for ruleset: %s", rulesetKey);
            return Optional.empty();

        } catch (Exception e) {
            LOG.errorf(e, "Error finding latest version for ruleset: %s", rulesetKey);
            return Optional.empty();
        }
    }

    /**
     * Invalidates the cached ruleset.
     *
     * @param rulesetKey the ruleset key
     * @param version    the ruleset version
     */
    public void invalidateCache(String rulesetKey, int version) {
        String cacheKey = rulesetKey + "/v" + version;
        rulesetCache.remove(cacheKey);
        LOG.debugf("Invalidated cache for ruleset: %s", cacheKey);
    }

    /**
     * Clears all cached rulesets.
     */
    public void clearCache() {
        rulesetCache.clear();
        LOG.info("Ruleset cache cleared");
    }

    /**
     * Checks if the ruleset storage is accessible.
     */
    public boolean isStorageAccessible() {
        try {
            HeadBucketRequest headBucketRequest = HeadBucketRequest.builder()
                    .bucket(bucketName)
                    .build();

            s3Client.headBucket(headBucketRequest);
            return true;

        } catch (Exception e) {
            LOG.warnf("S3 storage is not accessible: %s", e.getMessage());
            return false;
        }
    }

    /**
     * Gets the cache size for monitoring.
     */
    public int getCacheSize() {
        return rulesetCache.size();
    }

    public boolean isYamlFallbackEnabled() {
        return yamlFallbackEnabled;
    }

    private String extractVersion(String key) {
        // Expected format: "rulesets/{key}/v{version}/ruleset.yaml"
        int vIndex = key.lastIndexOf("/v");
        if (vIndex < 0) {
            return null;
        }

        String afterV = key.substring(vIndex + 2);
        int slashIndex = afterV.indexOf('/');

        if (slashIndex > 0) {
            return afterV.substring(0, slashIndex);
        } else if (!afterV.isEmpty()) {
            return afterV;
        }

        return null;
    }

    // ========== Compiled Ruleset JSON Parsing ==========

    private String buildRulesetPrefix(String country, String rulesetKey) {
        String prefix = pathPrefix.endsWith("/") ? pathPrefix : pathPrefix + "/";
        return prefix + rulesetEnvironment + "/" + country + "/" + rulesetKey + "/";
    }

    private String buildRulesetPrefix(String rulesetKey) {
        String prefix = pathPrefix.endsWith("/") ? pathPrefix : pathPrefix + "/";
        return prefix + rulesetEnvironment + "/" + rulesetKey + "/";
    }

    private byte[] loadArtifactBytes(String artifactUri) throws Exception {
        if (artifactUri == null || artifactUri.isBlank()) {
            return null;
        }
        URI uri = URI.create(artifactUri);
        String scheme = uri.getScheme();

        if ("s3".equalsIgnoreCase(scheme)) {
            String bucket = uri.getHost();
            String key = uri.getPath();
            if (key != null && key.startsWith("/")) {
                key = key.substring(1);
            }
            if (bucket == null || key == null) {
                return null;
            }
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .build();
            try (InputStream inputStream = s3Client.getObject(request)) {
                return inputStream.readAllBytes();
            }
        }

        if ("file".equalsIgnoreCase(scheme)) {
            Path path = Path.of(uri);
            return Files.readAllBytes(path);
        }

        LOG.warnf("Unsupported artifact URI scheme: %s", artifactUri);
        return null;
    }

    private boolean verifyChecksum(byte[] data, String checksum) {
        if (checksum == null || checksum.isBlank()) {
            return true;
        }
        String normalized = checksum.startsWith("sha256:") ? checksum.substring("sha256:".length()) : checksum;
        String computed = sha256Hex(data);
        return computed.equalsIgnoreCase(normalized);
    }

    private String sha256Hex(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to compute SHA-256 checksum", e);
        }
    }

    private Ruleset parseRuleset(byte[] artifactBytes, String rulesetKeyHint, Integer versionHint) throws Exception {
        JsonNode root = jsonMapper.readTree(artifactBytes);

        String rulesetKey = readString(root, "ruleset_key", "rulesetKey");
        if (rulesetKey == null) {
            rulesetKey = rulesetKeyHint;
        }

        Integer version = readInt(root, "ruleset_version", "rulesetVersion", "version");
        if (version == null) {
            version = versionHint;
        }

        String rulesetId = readString(root, "ruleset_id", "rulesetId");

        String executionMode = readString(root, "execution_mode");
        String evaluationMode = readString(root.path("evaluation"), "mode");
        String evaluationType = toEvaluationType(rulesetKey, executionMode, evaluationMode);
        if (executionMode == null && evaluationMode == null) {
            String ruleType = readString(root, "rule_type", "ruleType");
            if (ruleType != null && ruleType.toUpperCase().contains("MONITORING")) {
                evaluationType = "MONITORING";
            }
        }

        List<Rule> rules = new ArrayList<>();
        JsonNode rulesNode = root.get("rules");
        if (rulesNode != null && rulesNode.isArray()) {
            for (JsonNode ruleNode : rulesNode) {
                Rule rule = parseRule(ruleNode);
                if (rule != null) {
                    rules.add(rule);
                }
            }
        }

        Ruleset ruleset = new Ruleset(rulesetKey, version != null ? version : 0);
        ruleset.setName(rulesetKey);
        ruleset.setEvaluationType(evaluationType);
        ruleset.setRulesetId(rulesetId);
        ruleset.setRules(rules);
        ruleset.preSort();

        return ruleset;
    }

    private Rule parseRule(JsonNode ruleNode) {
        String ruleId = readString(ruleNode, "rule_id", "ruleId");
        if (ruleId == null) {
            LOG.warn("Skipping rule with missing rule_id");
            return null;
        }

        boolean enabled = readBoolean(ruleNode, "enabled", true);
        Integer priorityValue = readInt(ruleNode, "priority");
        int priority = priorityValue != null ? priorityValue : 0;

        String action = DecisionNormalizer.normalizeRuleAction(parseAction(ruleNode.get("action")));
        if (action == null) {
            action = "APPROVE";
        }

        String ruleVersionId = readString(ruleNode, "rule_version_id", "ruleVersionId");
        Integer ruleVersion = readInt(ruleNode, "rule_version", "ruleVersion");

        JsonNode conditionNode = ruleNode.get("condition");
        if (conditionNode == null || conditionNode.isNull()) {
            conditionNode = ruleNode.get("when");
        }

        List<Condition> conditions = extractLeafConditions(conditionNode);
        CompiledCondition compiledCondition = parseConditionNode(conditionNode);
        VelocityConfig velocity = parseVelocity(ruleNode.get("velocity"), action);
        RuleScope scope = parseScope(ruleNode.get("scope"));

        Rule rule = new Rule(ruleId, ruleId, action);
        rule.setPriority(priority);
        rule.setEnabled(enabled);
        rule.setConditions(conditions);
        rule.setCompiledCondition(compiledCondition);
        rule.setVelocity(velocity);
        rule.setScope(scope != null ? scope : RuleScope.GLOBAL);
        rule.setRuleVersionId(ruleVersionId);
        rule.setRuleVersion(ruleVersion);

        return rule;
    }

    private CompiledCondition parseConditionNode(JsonNode node) {
        if (node == null || node.isNull()) {
            return tx -> true;
        }

        if (node.has("and")) {
            return combineConditions(node.get("and"), true);
        }
        if (node.has("or")) {
            return combineConditions(node.get("or"), false);
        }
        if (node.has("not")) {
            return parseNotCondition(node.get("not"));
        }

        String type = readString(node, "type");
        if (type != null) {
            String normalizedType = type.trim().toLowerCase();
            return switch (normalizedType) {
                case "and" -> combineConditions(node.get("conditions"), true);
                case "or" -> combineConditions(node.get("conditions"), false);
                case "not" -> parseNotCondition(node.get("conditions"));
                case "condition" -> {
                    String operator = readString(node, "operator", "op");
                    if (operator == null) {
                        yield tx -> true;
                    }
                    yield compileLeafCondition(node, operator);
                }
                default -> tx -> true;
            };
        }

        String op = readString(node, "op", "operator");
        if (op == null) {
            return tx -> true;
        }

        String normalized = op.trim().toLowerCase();
        return switch (normalized) {
            case "and" -> combineConditions(node, true);
            case "or" -> combineConditions(node, false);
            case "not" -> parseNotCondition(node);
            default -> compileLeafCondition(node, normalized);
        };
    }

    private CompiledCondition combineConditions(JsonNode node, boolean useAnd) {
        List<CompiledCondition> children = new ArrayList<>();
        JsonNode args = node;
        if (args != null && !args.isArray()) {
            args = node.get("args");
            if (args == null) {
                args = node.get("conditions");
            }
        }
        if (args != null && args.isArray()) {
            for (JsonNode child : args) {
                children.add(parseConditionNode(child));
            }
        }
        if (children.isEmpty()) {
            return tx -> true;
        }
        CompiledCondition combined = children.get(0);
        for (int i = 1; i < children.size(); i++) {
            combined = useAnd ? combined.and(children.get(i)) : combined.or(children.get(i));
        }
        return combined;
    }

    private CompiledCondition parseNotCondition(JsonNode node) {
        if (node == null || node.isNull()) {
            return tx -> true;
        }
        JsonNode args = node;
        if (!node.isArray()) {
            JsonNode candidate = node.get("args");
            if (candidate == null) {
                candidate = node.get("conditions");
            }
            if (candidate != null) {
                args = candidate;
            }
        }
        if (args != null && args.isArray() && args.size() > 0) {
            return parseConditionNode(args.get(0)).not();
        }
        return parseConditionNode(args).not();
    }

    private CompiledCondition compileLeafCondition(JsonNode node, String operator) {
        Condition condition = buildConditionFromNode(node, operator);
        if (condition == null) {
            return tx -> true;
        }
        return ConditionCompiler.compile(condition);
    }

    private Condition buildConditionFromNode(JsonNode node, String operator) {
        String field = readString(node, "field");
        if (field == null) {
            return null;
        }

        Condition condition = new Condition();
        condition.setField(field);
        condition.setOperator(operator);

        JsonNode valueNode = node.get("value");
        if (valueNode != null && !valueNode.isNull()) {
            condition.setValue(jsonMapper.convertValue(valueNode, Object.class));
        }

        JsonNode valuesNode = node.get("values");
        if (valuesNode != null && valuesNode.isArray()) {
            condition.setValues(jsonMapper.convertValue(valuesNode, List.class));
        }

        return condition;
    }

    private List<Condition> extractLeafConditions(JsonNode node) {
        List<Condition> conditions = new ArrayList<>();
        collectLeafConditions(node, conditions);
        return conditions;
    }

    private void collectLeafConditions(JsonNode node, List<Condition> out) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.has("and")) {
            collectLeafConditions(node.get("and"), out);
            return;
        }
        if (node.has("or")) {
            collectLeafConditions(node.get("or"), out);
            return;
        }
        if (node.has("not")) {
            collectLeafConditions(node.get("not"), out);
            return;
        }

        String type = readString(node, "type");
        if (type != null) {
            String normalizedType = type.trim().toLowerCase();
            if ("and".equals(normalizedType) || "or".equals(normalizedType) || "not".equals(normalizedType)) {
                JsonNode conditions = node.get("conditions");
                collectLeafConditions(conditions, out);
                return;
            }
            if ("condition".equals(normalizedType)) {
                String operator = readString(node, "operator", "op");
                Condition condition = buildConditionFromNode(node, operator);
                if (condition != null) {
                    out.add(condition);
                }
                return;
            }
        }

        if (node.isArray()) {
            for (JsonNode child : node) {
                collectLeafConditions(child, out);
            }
            return;
        }

        String op = readString(node, "op", "operator");
        if (op == null) {
            return;
        }
        String normalized = op.trim().toLowerCase();
        if ("and".equals(normalized) || "or".equals(normalized) || "not".equals(normalized)) {
            JsonNode args = node.get("args");
            if (args == null) {
                args = node.get("conditions");
            }
            if (args != null && args.isArray()) {
                for (JsonNode child : args) {
                    collectLeafConditions(child, out);
                }
            }
            return;
        }
        Condition condition = buildConditionFromNode(node, normalized);
        if (condition != null) {
            out.add(condition);
        }
    }

    private VelocityConfig parseVelocity(JsonNode velocityNode, String ruleAction) {
        if (velocityNode == null || velocityNode.isNull()) {
            return null;
        }
        VelocityConfig config = jsonMapper.convertValue(velocityNode, VelocityConfig.class);
        String velocityAction = DecisionNormalizer.normalizeRuleAction(config.getAction());
        if (velocityAction != null) {
            config.setAction(velocityAction);
        }
        if (config.getAction() == null) {
            config.setAction(ruleAction);
        }
        return config;
    }

    private RuleScope parseScope(JsonNode scopeNode) {
        if (scopeNode == null || scopeNode.isNull() || scopeNode.isEmpty()) {
            return RuleScope.GLOBAL;
        }

        RuleScope scope = RuleScope.fromScopeNode(scopeNode, jsonMapper);
        return scope != null ? scope : RuleScope.GLOBAL;
    }

    private String parseAction(JsonNode actionNode) {
        if (actionNode == null || actionNode.isNull()) {
            return null;
        }
        if (actionNode.isTextual()) {
            return actionNode.asText().toUpperCase();
        }
        JsonNode decisionNode = actionNode.get("decision");
        if (decisionNode != null && decisionNode.isTextual()) {
            return decisionNode.asText().toUpperCase();
        }
        JsonNode actionField = actionNode.get("action");
        if (actionField != null && actionField.isTextual()) {
            return actionField.asText().toUpperCase();
        }
        return null;
    }

    private Integer readInt(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && value.isNumber()) {
                return value.asInt();
            }
        }
        return null;
    }

    private boolean readBoolean(JsonNode node, String name, boolean defaultValue) {
        JsonNode value = node.get(name);
        if (value == null || value.isNull()) {
            return defaultValue;
        }
        return value.asBoolean(defaultValue);
    }

    private String readString(JsonNode node, String... names) {
        for (String name : names) {
            JsonNode value = node.get(name);
            if (value != null && value.isTextual()) {
                return value.asText();
            }
        }
        return null;
    }

    private String toEvaluationType(String rulesetKey, String executionMode, String evaluationMode) {
        String mode = executionMode != null ? executionMode : evaluationMode;
        if (mode != null) {
            switch (mode.toUpperCase()) {
                case "FIRST_MATCH":
                    return "AUTH";
                case "ALL_MATCHING":
                    return "MONITORING";
            }
        }
        if (rulesetKey != null && rulesetKey.toUpperCase().contains("MONITORING")) {
            return "MONITORING";
        }
        return "AUTH";
    }

    /**
     * Loads a compiled ruleset from a local file path.
     * Used for testing without MinIO.
     *
     * @param filePath the path to the compiled ruleset JSON file
     * @param rulesetKeyHint hint for the ruleset key
     * @return the parsed ruleset
     * @throws Exception if parsing fails
     */
    public Ruleset loadRulesetFromFile(String filePath, String rulesetKeyHint) throws Exception {
        byte[] content = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
        return parseRuleset(content, rulesetKeyHint, null);
    }
}
