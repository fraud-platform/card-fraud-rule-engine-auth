package com.fraud.engine.util;

import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link LatencyHistogram}: bucket boundary semantics, percentile
 * estimation via linear interpolation, empty-histogram safety, and basic
 * concurrent-recording correctness.
 */
class LatencyHistogramTest {

    private static final double DELTA = 0.0001;

    @Test
    void emptyHistogramHasZeroCountAndZeroPercentilesNoDivisionByZero() {
        LatencyHistogram histogram = new LatencyHistogram();

        LatencyHistogram.Snapshot snapshot = histogram.snapshot();

        assertEquals(0L, snapshot.count);
        assertEquals(0.0, snapshot.sumMs, DELTA);
        assertEquals(0.0, snapshot.p50Ms, DELTA);
        assertEquals(0.0, snapshot.p95Ms, DELTA);
        assertEquals(0.0, snapshot.p99Ms, DELTA);
        for (long v : snapshot.buckets.values()) {
            assertEquals(0L, v);
        }
    }

    @Test
    void exactlyOneMillisecondFallsInLe1msBucket() {
        LatencyHistogram histogram = new LatencyHistogram();

        histogram.record(1_000_000L); // exactly 1ms

        Map<String, Long> buckets = histogram.snapshot().buckets;
        assertEquals(1L, buckets.get("le_1ms"));
        assertEquals(1L, buckets.get("le_2ms")); // cumulative
        assertEquals(1L, buckets.get("inf"));
    }

    @Test
    void justOverOneMillisecondFallsInLe2msBucketNotLe1ms() {
        LatencyHistogram histogram = new LatencyHistogram();

        histogram.record(1_500_000L); // 1.5ms

        Map<String, Long> buckets = histogram.snapshot().buckets;
        assertEquals(0L, buckets.get("le_1ms"));
        assertEquals(1L, buckets.get("le_2ms"));
        assertEquals(1L, buckets.get("inf"));
    }

    @Test
    void exactlyOneHundredMillisecondsFallsInLe100msBucket() {
        LatencyHistogram histogram = new LatencyHistogram();

        histogram.record(100_000_000L); // exactly 100ms

        Map<String, Long> buckets = histogram.snapshot().buckets;
        assertEquals(1L, buckets.get("le_100ms"));
        assertEquals(1L, buckets.get("inf"));
    }

    @Test
    void aboveOneHundredMillisecondsOnlyCountsTowardInf() {
        LatencyHistogram histogram = new LatencyHistogram();

        histogram.record(250_000_000L); // 250ms

        LatencyHistogram.Snapshot snapshot = histogram.snapshot();
        Map<String, Long> buckets = snapshot.buckets;
        assertEquals(0L, buckets.get("le_100ms"));
        assertEquals(1L, buckets.get("inf"));
        assertEquals(1L, snapshot.count);
        assertEquals(250.0, snapshot.sumMs, DELTA);
    }

    @Test
    void percentilesInterpolateWithinBucketForKnownDistribution() {
        LatencyHistogram histogram = new LatencyHistogram();

        // 10 samples at exactly 1ms, 10 samples at exactly 2ms => total 20
        for (int i = 0; i < 10; i++) {
            histogram.record(1_000_000L);
        }
        for (int i = 0; i < 10; i++) {
            histogram.record(2_000_000L);
        }

        LatencyHistogram.Snapshot snapshot = histogram.snapshot();
        assertEquals(20L, snapshot.count);
        assertEquals(30.0, snapshot.sumMs, DELTA);
        // rank(50%) = 10 -> lands exactly at the le_1ms bucket boundary
        assertEquals(1.0, snapshot.p50Ms, DELTA);
        // rank(95%) = 19 -> 90% into the le_2ms bucket (bound 1ms..2ms)
        assertEquals(1.9, snapshot.p95Ms, DELTA);
        // rank(99%) = 19.8 -> 98% into the le_2ms bucket
        assertEquals(1.98, snapshot.p99Ms, DELTA);
    }

    @Test
    void percentilesInOverflowBucketReportLastFiniteBound() {
        LatencyHistogram histogram = new LatencyHistogram();

        histogram.record(500_000_000L); // 500ms, lands only in +Inf bucket

        LatencyHistogram.Snapshot snapshot = histogram.snapshot();
        assertEquals(100.0, snapshot.p50Ms, DELTA);
        assertEquals(100.0, snapshot.p95Ms, DELTA);
        assertEquals(100.0, snapshot.p99Ms, DELTA);
    }

    @Test
    void concurrentRecordingSmokeTestNoLostUpdates() throws InterruptedException {
        LatencyHistogram histogram = new LatencyHistogram();
        int threads = 8;
        int recordsPerThread = 5_000;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch ready = new CountDownLatch(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);

        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                ready.countDown();
                try {
                    start.await();
                    for (int i = 0; i < recordsPerThread; i++) {
                        histogram.record(3_000_000L); // 3ms each
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }

        assertTrue(ready.await(5, TimeUnit.SECONDS));
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        LatencyHistogram.Snapshot snapshot = histogram.snapshot();
        assertEquals((long) threads * recordsPerThread, snapshot.count);
        assertEquals((long) threads * recordsPerThread, snapshot.buckets.get("le_5ms"));
        assertEquals(0L, snapshot.buckets.get("le_2ms"));
    }
}
