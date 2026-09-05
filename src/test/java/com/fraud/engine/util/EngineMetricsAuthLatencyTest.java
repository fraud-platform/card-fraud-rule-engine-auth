package com.fraud.engine.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that {@link EngineMetrics} correctly records and exposes the
 * AUTH server-side latency histogram.
 */
class EngineMetricsAuthLatencyTest {

    @Test
    void recordAuthLatencyIncreasesHistogramCount() {
        EngineMetrics metrics = new EngineMetrics();

        metrics.recordAuthLatency(2_000_000L); // 2ms
        metrics.recordAuthLatency(4_000_000L); // 4ms

        LatencyHistogram.Snapshot snapshot = metrics.authLatencySnapshot();
        assertEquals(2L, snapshot.count);
        assertEquals(6.0, snapshot.sumMs, 0.0001);
    }

    @Test
    void authLatencySnapshotExposesAllExpectedBucketKeys() {
        EngineMetrics metrics = new EngineMetrics();

        LatencyHistogram.Snapshot snapshot = metrics.authLatencySnapshot();

        assertNotNull(snapshot.buckets);
        for (String key : new String[] {"le_1ms", "le_2ms", "le_5ms", "le_10ms", "le_20ms", "le_50ms", "le_100ms", "inf"}) {
            assertTrue(snapshot.buckets.containsKey(key), "missing bucket key: " + key);
        }
    }
}
