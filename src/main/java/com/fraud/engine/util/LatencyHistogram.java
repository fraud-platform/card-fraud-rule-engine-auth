package com.fraud.engine.util;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.LongAdder;

/**
 * Thread-safe fixed-bucket latency histogram, purpose-built for measuring
 * server-side request latency without pulling in Micrometer or any other
 * new dependency.
 * <p>
 * Bucket upper bounds are fixed at 1, 2, 5, 10, 20, 50, 100 milliseconds
 * plus an implicit +Inf overflow bucket (8 buckets total). A sample lands
 * in the first bucket whose upper bound is greater than or equal to the
 * sample value ({@code <=} semantics) &mdash; e.g. a sample of exactly 1ms
 * lands in the {@code le_1ms} bucket, not {@code le_2ms}.
 * <p>
 * {@link #record(long)} is allocation-free and lock-free on the hot path:
 * it increments exactly one {@link LongAdder} bucket counter plus the
 * total count and sum-of-micros adders. {@link #snapshot()} is the only
 * place that does O(bucket count) work (prefix-summing per-bucket counts
 * into the cumulative counts exposed to callers, and estimating
 * percentiles) and is expected to be called rarely (e.g. from a metrics
 * endpoint), not from the request hot path.
 */
public final class LatencyHistogram {

    /** Finite bucket upper bounds, in milliseconds. */
    private static final double[] BUCKET_UPPER_BOUNDS_MS = {1, 2, 5, 10, 20, 50, 100};

    /** Same bounds expressed in microseconds (record() truncates to micro precision). */
    private static final long[] BUCKET_UPPER_BOUNDS_MICROS = {1_000, 2_000, 5_000, 10_000, 20_000, 50_000, 100_000};

    /** Cumulative bucket key names, in bound order, matching {@link #BUCKET_UPPER_BOUNDS_MS}. */
    private static final String[] BUCKET_KEYS = {
            "le_1ms", "le_2ms", "le_5ms", "le_10ms", "le_20ms", "le_50ms", "le_100ms"
    };

    private static final String OVERFLOW_KEY = "inf";

    /** Per-bucket counts (NOT cumulative) so record() only ever touches one bucket adder. */
    private final LongAdder[] bucketCounts;
    private final LongAdder count = new LongAdder();
    private final LongAdder sumMicros = new LongAdder();

    public LatencyHistogram() {
        // One extra slot for the +Inf overflow bucket.
        this.bucketCounts = new LongAdder[BUCKET_UPPER_BOUNDS_MICROS.length + 1];
        for (int i = 0; i < bucketCounts.length; i++) {
            bucketCounts[i] = new LongAdder();
        }
    }

    /**
     * Records one latency sample.
     *
     * @param nanos elapsed time in nanoseconds (as from {@code System.nanoTime()} deltas).
     *              Internally truncated to microsecond precision for bucket assignment and sum.
     */
    public void record(long nanos) {
        long micros = nanos / 1_000L;
        count.increment();
        sumMicros.add(micros);
        bucketCounts[bucketIndex(micros)].increment();
    }

    private static int bucketIndex(long micros) {
        for (int i = 0; i < BUCKET_UPPER_BOUNDS_MICROS.length; i++) {
            if (micros <= BUCKET_UPPER_BOUNDS_MICROS[i]) {
                return i;
            }
        }
        return BUCKET_UPPER_BOUNDS_MICROS.length; // overflow (+Inf) bucket
    }

    /**
     * Takes a consistent-enough snapshot of the histogram for reporting.
     * Cumulative bucket counts and percentiles are computed here, not on the hot path.
     */
    public Snapshot snapshot() {
        long[] raw = new long[bucketCounts.length];
        for (int i = 0; i < bucketCounts.length; i++) {
            raw[i] = bucketCounts[i].sum();
        }

        long[] cumulative = new long[raw.length];
        long running = 0;
        for (int i = 0; i < raw.length; i++) {
            running += raw[i];
            cumulative[i] = running;
        }

        long total = count.sum();
        double sumMs = sumMicros.sum() / 1000.0;

        Map<String, Long> buckets = new LinkedHashMap<>();
        for (int i = 0; i < BUCKET_KEYS.length; i++) {
            buckets.put(BUCKET_KEYS[i], cumulative[i]);
        }
        buckets.put(OVERFLOW_KEY, cumulative[cumulative.length - 1]);

        double p50 = estimatePercentile(cumulative, total, 0.50);
        double p95 = estimatePercentile(cumulative, total, 0.95);
        double p99 = estimatePercentile(cumulative, total, 0.99);

        return new Snapshot(total, sumMs, p50, p95, p99, buckets);
    }

    /**
     * Estimates a percentile via linear interpolation within the bucket the target rank falls in.
     * <p>
     * If the target rank falls in the +Inf overflow bucket (i.e. beyond the last finite bound),
     * the last finite bound (100ms) is returned rather than +Inf &mdash; documented approximation.
     * An empty histogram (total == 0) returns 0.0, avoiding division by zero.
     */
    private static double estimatePercentile(long[] cumulative, long total, double p) {
        if (total == 0) {
            return 0.0;
        }
        double target = p * total;
        long prevCumulative = 0;
        double prevBoundMs = 0.0;
        for (int i = 0; i < BUCKET_UPPER_BOUNDS_MS.length; i++) {
            long bucketCumulative = cumulative[i];
            if (bucketCumulative >= target) {
                double boundMs = BUCKET_UPPER_BOUNDS_MS[i];
                long bucketCount = bucketCumulative - prevCumulative;
                if (bucketCount <= 0) {
                    return boundMs;
                }
                double fraction = (target - prevCumulative) / bucketCount;
                return prevBoundMs + fraction * (boundMs - prevBoundMs);
            }
            prevCumulative = bucketCumulative;
            prevBoundMs = BUCKET_UPPER_BOUNDS_MS[i];
        }
        // Target rank falls beyond the last finite bound, into the +Inf bucket.
        return BUCKET_UPPER_BOUNDS_MS[BUCKET_UPPER_BOUNDS_MS.length - 1];
    }

    /**
     * Immutable point-in-time snapshot of the histogram, shaped for direct JSON exposure.
     * {@code buckets} keys are cumulative ("le_Xms" = count of samples &lt;= X ms), matching
     * standard cumulative-histogram convention; {@code inf} is the running total (all samples).
     */
    public static final class Snapshot {
        public final long count;
        public final double sumMs;
        public final double p50Ms;
        public final double p95Ms;
        public final double p99Ms;
        public final Map<String, Long> buckets;

        Snapshot(long count, double sumMs, double p50Ms, double p95Ms, double p99Ms, Map<String, Long> buckets) {
            this.count = count;
            this.sumMs = sumMs;
            this.p50Ms = p50Ms;
            this.p95Ms = p95Ms;
            this.p99Ms = p99Ms;
            this.buckets = buckets;
        }

        public long getCount() {
            return count;
        }

        public double getSumMs() {
            return sumMs;
        }

        public double getP50Ms() {
            return p50Ms;
        }

        public double getP95Ms() {
            return p95Ms;
        }

        public double getP99Ms() {
            return p99Ms;
        }

        public Map<String, Long> getBuckets() {
            return buckets;
        }
    }
}
