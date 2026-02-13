# JFR Profiling Guide

Complete step-by-step guide for capturing and analyzing JFR recordings during load tests.

## Prerequisites

- Java 21 JDK with `jfr` and `jcmd` tools
- Application JAR built: `target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar`
- Infrastructure running: Redis, MinIO, Kafka (optional for AUTH)
- Load testing harness: `card-fraud-e2e-load-testing` repository

---

## Method 1: Dynamic JFR with jcmd (RECOMMENDED)

This method gives you full control over when to start/stop recording.

### Step 1: Start Application WITHOUT JFR

```bash
cd /c/Users/kanna/github/card-fraud-rule-engine

# Start JAR with standard config
APP_RULESET_STARTUP_LOAD_ENABLED=true \
doppler run --config local -- \
  java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar \
  > /tmp/rule-engine.log 2>&1 &

# Wait for startup
sleep 15

# Verify health
curl -s http://localhost:8081/health | python -m json.tool
```

### Step 2: Find Java Process ID

```bash
jps -l | grep card-fraud
# Output: 78320 target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar
```

### Step 3: Start JFR Recording

```bash
# Start recording with jcmd (180s duration, profile settings)
jcmd <PID> JFR.start name=loadtest \
  settings=profile \
  duration=180s \
  filename=/c/Users/kanna/github/card-fraud-rule-engine/jfr-recording.jfr

# Example:
jcmd 78320 JFR.start name=loadtest settings=profile duration=180s filename=/c/Users/kanna/github/card-fraud-rule-engine/jfr-recording.jfr
```

**Output:**
```
78320:
Started recording 1. The result will be written to:

C:\Users\kanna\github\card-fraud-rule-engine\jfr-recording.jfr
```

### Step 4: Run Load Test IMMEDIATELY

```bash
cd /c/Users/kanna/github/card-fraud-e2e-load-testing

uv run lt-run \
  --service rule-engine \
  --users=100 \
  --spawn-rate=10 \
  --run-time=2m \
  --scenario baseline \
  --headless
```

### Step 5: Dump Recording (Optional)

If you want to stop recording early and dump results:

```bash
# Dump the recording without stopping it
jcmd <PID> JFR.dump name=loadtest filename=/c/Users/kanna/github/card-fraud-rule-engine/jfr-dump.jfr

# Or stop the recording and dump
jcmd <PID> JFR.stop name=loadtest
```

### Step 6: Verify Recording

```bash
# Check file size (should be several MB if it captured traffic)
ls -lh /c/Users/kanna/github/card-fraud-rule-engine/jfr-recording.jfr

# View summary
jfr summary /c/Users/kanna/github/card-fraud-rule-engine/jfr-recording.jfr
```

**Expected Output:**
```
Version: 2.1
Chunks: 1
Start: 2026-02-08 09:44:26 (UTC)
Duration: 158 s

Event Type                              Count  Size (bytes)
=============================================================
jdk.ExecutionSample                      1331         18822  ← Should have 1000+ samples
```

---

## Method 2: JFR at JVM Startup (NOT RECOMMENDED)

**Problem:** Recording often stops before load test starts due to timing issues.

```bash
# Start JAR with JFR enabled at startup
java -XX:StartFlightRecording=duration=600s,filename=flight.jfr,settings=profile \
  -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar

# Issue: 600s timer starts IMMEDIATELY when JVM starts
# By the time app starts (10s) + you run load test (10s),
# you've lost 20s of the 600s window
```

**Verdict:** Use Method 1 (jcmd) instead.

---

## Analyzing JFR Recordings

### Quick Analysis: Command Line

#### 1. Find Most Sampled Threads

```bash
jfr print --events jdk.ExecutionSample <file>.jfr \
  | grep "sampledThread" \
  | sort | uniq -c | sort -rn | head -20
```

**What to look for:**
- High sample counts on specific threads indicate bottlenecks
- `kafka-producer-network-thread`: Kafka blocking
- `executor-thread-XXX`: Worker thread execution (your code)
- `vert.x-eventloop-thread-X`: Event loop (network I/O)

#### 2. Find Top CPU-Consuming Methods

```bash
jfr print --events jdk.ExecutionSample <file>.jfr \
  | grep -E "(com\.fraud\.|com\.fasterxml\.jackson|java\.time\.|org\.apache\.kafka)" \
  | sort | uniq -c | sort -rn | head -30
```

**What to look for:**
- `com.fasterxml.jackson.*`: JSON serialization overhead
- `java.time.*`: DateTime formatting overhead
- `org.apache.kafka.*`: Kafka producer overhead
- `com.fraud.engine.*`: Your application code

#### 3. Find Blocking Operations

```bash
jfr print --events jdk.ThreadPark <file>.jfr | head -100
jfr print --events jdk.JavaMonitorEnter <file>.jfr | head -100
jfr print --events jdk.JavaMonitorWait <file>.jfr | head -100
```

**What to look for:**
- High `ThreadPark` counts: Threads waiting (Redis, Kafka)
- High `JavaMonitorEnter`: Lock contention

#### 4. Check GC Overhead

```bash
jfr print --events jdk.GCPhasePause <file>.jfr
jfr print --events jdk.GarbageCollection <file>.jfr
```

**What to look for:**
- Long pause times (>50ms) indicate GC issues
- High GC frequency indicates memory pressure

#### 5. Check Object Allocation Hotspots

```bash
jfr print --events jdk.ObjectAllocationSample <file>.jfr \
  | head -100
```

**What to look for:**
- High allocation rates in specific methods
- Indicates potential areas for object pooling

### Detailed Analysis: JDK Mission Control (GUI)

```bash
# Install JMC
# Download from: https://www.oracle.com/java/technologies/jdk-mission-control.html

# Open JFR file
jmc <file>.jfr
```

**Key Views:**
1. **Method Profiling → Hot Methods**: Top CPU consumers
2. **Threads → Thread Statistics**: Time spent in each state
3. **Lock Instances**: Lock contention analysis
4. **Memory → Allocations**: Object allocation hotspots
5. **GC Times**: Garbage collection overhead

---

## Common Issues & Solutions

### Issue 1: Recording is 0 bytes or too small

**Cause:** Recording hasn't finished or stopped early.

**Solution:**
```bash
# Manually dump the recording
jcmd <PID> JFR.dump name=loadtest filename=<output>.jfr

# Or check if recording is still running
jcmd <PID> JFR.check
```

### Issue 2: Only 13 seconds of data captured

**Cause:** JFR duration timer started at JVM startup, not when you started recording.

**Solution:** Use Method 1 (jcmd) instead of Method 2 (JVM startup).

### Issue 3: No ExecutionSample events or very few (<100)

**Cause:** Using `default` settings instead of `profile` settings.

**Solution:** Always use `settings=profile`:
```bash
jcmd <PID> JFR.start name=loadtest settings=profile ...
```

### Issue 4: Recording only captures startup, not load test

**Cause:** Load test started after recording finished.

**Solution:** Start recording → immediately start load test (within 10 seconds).

### Issue 5: No worker thread samples

**Cause:** Worker threads may be named differently (e.g., `executor-thread` not `vert.x-worker`).

**Solution:** Check all thread names first:
```bash
jfr print --events jdk.ExecutionSample <file>.jfr \
  | grep "sampledThread" | sort | uniq
```

---

## Best Practices

1. **Always use jcmd method** - More reliable than startup JFR
2. **Use profile settings** - Captures more detail than default
3. **Start recording THEN load test** - Don't wait between them
4. **Duration = load test duration + 60s** - Add buffer for warmup
5. **Check file size immediately** - Should be 5-10MB for 2-minute test
6. **Verify ExecutionSample count** - Should have 1000+ samples
7. **Focus on top 10 methods** - They usually account for 80% of CPU time
8. **Compare before/after** - Always keep baseline JFR recordings

---

## Example Complete Workflow

```bash
# 1. Build JAR
cd /c/Users/kanna/github/card-fraud-rule-engine
doppler run --config local -- mvn package -DskipTests -Dquarkus.package.jar.type=uber-jar

# 2. Start JAR
doppler run --config local -- java -jar target/card-fraud-rule-engine-1.0.0-SNAPSHOT-runner.jar \
  > /tmp/rule-engine.log 2>&1 &

# 3. Wait for startup
sleep 15 && curl -s http://localhost:8081/health | python -m json.tool

# 4. Get PID
PID=$(jps -l | grep card-fraud-rule-engine | awk '{print $1}')
echo "PID: $PID"

# 5. Start JFR recording
jcmd $PID JFR.start name=loadtest settings=profile duration=180s \
  filename=/c/Users/kanna/github/card-fraud-rule-engine/jfr-$(date +%Y%m%d-%H%M%S).jfr

# 6. Run load test IMMEDIATELY
cd /c/Users/kanna/github/card-fraud-e2e-load-testing
uv run lt-run --service rule-engine --users=100 --spawn-rate=10 \

# 7. Wait for load test to finish
sleep 130

# 8. Dump recording (don't wait for full 180s)
jcmd $PID JFR.dump name=loadtest \
  filename=/c/Users/kanna/github/card-fraud-rule-engine/jfr-final-$(date +%Y%m%d-%H%M%S).jfr

# 9. Analyze
JFR_FILE=$(ls -t /c/Users/kanna/github/card-fraud-rule-engine/jfr-final-*.jfr | head -1)
echo "Analyzing: $JFR_FILE"

# Check summary
jfr summary $JFR_FILE

# Find hot methods
jfr print --events jdk.ExecutionSample $JFR_FILE \
  | grep -E "(com\.fraud\.|com\.fasterxml\.jackson|java\.time)" \
  | sort | uniq -c | sort -rn | head -20

# Find hot threads
jfr print --events jdk.ExecutionSample $JFR_FILE \
  | grep "sampledThread" | sort | uniq -c | sort -rn | head -20
```

---

## Reference Files

- **This Session's Recording:** `jfr-dynamic-dump.jfr` (6.3MB, 158s, 1331 samples)
- **This Session's Analysis:** `JFR-ANALYSIS-2026-02-08.md`
- **Load Test Result:** `card-fraud-e2e-load-testing/html-reports/run-summary-20260208-151640.json`

---

## Next Steps After JFR Analysis

1. Identify top 3 CPU-consuming components
2. Calculate % of total CPU time for each
3. Estimate latency impact (CPU% × total latency)
4. Prioritize optimizations by impact vs effort
5. Implement, test, and capture new JFR recording
6. Compare before/after to validate improvement
