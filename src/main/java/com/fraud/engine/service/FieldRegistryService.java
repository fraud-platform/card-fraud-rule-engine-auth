package com.fraud.engine.service;

import com.fraud.engine.domain.FieldRegistry;
import com.fraud.engine.dto.FieldRegistryArtifact;
import com.fraud.engine.dto.FieldRegistryEntry;
import com.fraud.engine.loader.FieldRegistryLoader;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Service for managing field registry with in-memory caching.
 * <p>
 * This service loads field definitions from S3/MinIO at startup and provides
 * fast lookup by field ID or field name. It includes hot-reload support
 * and builtin fallback for S3 unavailability.
 * <p>
 * The service maintains two indexes for fast lookup:
 * <ul>
 *   <li>byId: field ID -> FieldRegistryEntry</li>
 *   <li>keyToId: normalized field name -> field ID</li>
 * </ul>
 */
@ApplicationScoped
public class FieldRegistryService {

    private static final Logger LOG = Logger.getLogger(FieldRegistryService.class);

    private final FieldRegistryLoader loader;

    // Current registry (volatile for safe publication)
    private volatile FieldRegistryArtifact registry;

    // Indexes for fast lookup
    private final Map<Integer, FieldRegistryEntry> byId = new ConcurrentHashMap<>();
    private final Map<String, Integer> keyToId = new ConcurrentHashMap<>();

    @Inject
    public FieldRegistryService(FieldRegistryLoader loader) {
        this.loader = loader;
    }

    @PostConstruct
    void init() {
        try {
            LOG.info("Initializing FieldRegistryService...");
            reload();
            LOG.infof("FieldRegistryService initialized with %d fields (version %d)",
                    getRegistryVersion(), getFieldCount());
        } catch (Exception e) {
            LOG.error("Failed to initialize FieldRegistryService", e);
            // Ensure we have a working registry even on init failure
            if (registry == null) {
                registry = loader.loadBuiltin();
                rebuildIndexes();
            }
        }
    }

    /**
     * Gets the field ID for a given field name.
     * <p>
     * First checks the dynamic registry, then falls back to the
     * static {@link FieldRegistry} constants for backward compatibility.
     *
     * @param fieldName the field name (e.g., "card_hash", "amount")
     * @return the field ID, or {@link FieldRegistry#UNKNOWN} if not found
     */
    public int getFieldId(String fieldName) {
        if (fieldName == null) {
            return FieldRegistry.UNKNOWN;
        }

        // Try dynamic registry first
        Integer id = keyToId.get(normalize(fieldName));
        if (id != null) {
            return id;
        }

        // Fallback to static FieldRegistry for backward compatibility
        return FieldRegistry.fromName(fieldName);
    }

    /**
     * Gets the field entry for a given field ID.
     *
     * @param fieldId the field ID
     * @return the field entry, or empty if not found
     */
    public Optional<FieldRegistryEntry> getField(int fieldId) {
        return Optional.ofNullable(byId.get(fieldId));
    }

    /**
     * Gets the field entry for a given field name.
     *
     * @param fieldName the field name
     * @return the field entry, or empty if not found
     */
    public Optional<FieldRegistryEntry> getFieldByName(String fieldName) {
        Integer id = keyToId.get(normalize(fieldName));
        if (id != null) {
            return Optional.ofNullable(byId.get(id));
        }
        return Optional.empty();
    }

    /**
     * Returns the current registry version.
     *
     * @return the registry version
     */
    public int getRegistryVersion() {
        FieldRegistryArtifact current = registry;
        return current != null ? current.registryVersion : 0;
    }

    /**
     * Returns the number of fields in the registry.
     *
     * @return the field count
     */
    public int getFieldCount() {
        return byId.size();
    }

    /**
     * Returns whether the registry was loaded from S3 (vs builtin fallback).
     *
     * @return true if loaded from S3, false if using builtin
     */
    public boolean isLoadedFromS3() {
        FieldRegistryArtifact current = registry;
        return current != null && !"builtin".equals(current.createdBy);
    }

    /**
     * Reloads the field registry from S3.
     * <p>
     * Called by the watcher on version changes or can be called manually.
     * Performs atomic swap of the in-memory registry.
     */
    public void reload() {
        LOG.info("Reloading field registry...");

        try {
            FieldRegistryArtifact newRegistry = loader.loadLatest();

            // Build new indexes first (fail fast if there's an issue)
            Map<Integer, FieldRegistryEntry> newById = new ConcurrentHashMap<>();
            Map<String, Integer> newKeyToId = new ConcurrentHashMap<>();

            buildIndexes(newRegistry.getFields(), newById, newKeyToId);

            // Atomic swap
            registry = newRegistry;
            byId.clear();
            byId.putAll(newById);
            keyToId.clear();
            keyToId.putAll(newKeyToId);

            LOG.infof("Field registry reloaded: version=%d, fields=%d, source=%d",
                    newRegistry.getRegistryVersion(),
                    newById.size(),
                    newRegistry.getCreatedBy());

        } catch (Exception e) {
            LOG.errorf(e, "Failed to reload field registry, keeping current version");
            throw e;
        }
    }

    /**
     * Gets the source of the current registry (S3 or builtin).
     *
     * @return the source description
     */
    public String getSource() {
        FieldRegistryArtifact current = registry;
        if (current == null) {
            return "unknown";
        }
        return "builtin".equals(current.getCreatedBy()) ? "builtin" : "s3";
    }

    /**
     * Checks if the S3 storage is accessible.
     *
     * @return true if S3 is accessible, false otherwise
     */
    public boolean isStorageAccessible() {
        return loader.isStorageAccessible();
    }

    // ========== Helper Methods ==========

    /**
     * Normalizes a field name for case-insensitive lookup.
     *
     * @param fieldName the field name to normalize
     * @return the normalized (lowercase) field name
     */
    private String normalize(String fieldName) {
        return fieldName.toLowerCase().trim();
    }

    private void buildIndexes(List<FieldRegistryEntry> fields,
                              Map<Integer, FieldRegistryEntry> byIdMap,
                              Map<String, Integer> keyToIdMap) {
        if (fields == null) {
            return;
        }
        for (FieldRegistryEntry entry : fields) {
            byIdMap.put(entry.getFieldId(), entry);
            keyToIdMap.put(normalize(entry.getFieldKey()), entry.getFieldId());

            String staticName = FieldRegistry.getName(entry.getFieldId());
            if (!"UNKNOWN".equals(staticName)) {
                keyToIdMap.put(normalize(staticName), entry.getFieldId());
            }
        }
    }

    /**
     * Rebuilds the indexes from the current registry.
     * Called during initialization and reload.
     */
    private void rebuildIndexes() {
        byId.clear();
        keyToId.clear();

        FieldRegistryArtifact current = registry;
        buildIndexes(current != null ? current.getFields() : null, byId, keyToId);
    }
}
