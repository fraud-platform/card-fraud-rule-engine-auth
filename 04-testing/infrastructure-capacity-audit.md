# Infrastructure Capacity Audit - Load Test Optimization

## Executive Summary

**Current Issue:** Pool sizes (Redis=20, Workers=20) were chosen arbitrarily without considering actual container resource limits.

**Finding:** Several containers have **NO resource limits** or **insufficient limits** for 100-user load tests.

**Impact:** We're hitting infrastructure bottlenecks (P95=320ms, P99=870ms) because containers are competing for host resources.

**Recommendation:** Add proper resource limits and calculate optimal pool sizes based on actual available resources.

---

## Current Infrastructure Configuration

### Infrastructure Containers (docker-compose.yml)

| Service | Image | Memory Limit | CPU Limit | Notes |
|---------|-------|--------------|-----------|-------|
| **Redis** | redis:8.4-alpine | **256MB** | ❌ None | Via `--maxmemory 256mb` |
| **Redpanda** | redpanda:v24.3.11 | **1GB** | **1 core** | Via `--memory 1G --smp 1` |
| **PostgreSQL** | postgres:18 | ❌ None | ❌ None | **UNBOUNDED** |
| **MinIO** | minio:latest | ❌ None | ❌ None | **UNBOUNDED** |

### Application Containers (docker-compose.apps.yml)

| Service | Memory Limit | Memory Reservation | CPU Limit | JVM Heap | Notes |
|---------|--------------|-------------------|-----------|----------|-------|
| **Rule Engine** | **2GB** | **1GB** | ❌ None | ❌ Not set | **JVM doesn't know about limit!** |
| **Rule Management** | ❌ None | ❌ None | ❌ None | N/A | Python/FastAPI |
| **Transaction Management** | ❌ None | ❌ None | ❌ None | N/A | Python/FastAPI |
| **Intelligence Portal** | ❌ None | ❌ None | ❌ None | N/A | Nginx/React |

---

## Critical Issues

### Issue 1: Rule Engine - JVM Memory Not Configured ⚠️

**Current:**
```yaml
deploy:
  resources:
    limits:
      memory: 2G      # Docker knows
    reservations:
      memory: 1G
environment:
  # NO -Xmx / -Xms flags!
```

**Problem:**
- Container has 2GB limit
- JVM doesn't know about it (uses default = 1/4 of **host RAM**)
- On a 16GB host: JVM will try to allocate ~4GB
- **Result:** OOM kills or container restarts under load

**Fix Required:**
```yaml
environment:
  - JAVA_OPTS=-Xms1G -Xmx1536M  # Leave 512MB for non-heap
```

**Rationale:**
- Container limit: 2GB
- JVM heap: 1.5GB (75%)
- Non-heap (MetaSpace, threads, native): 512MB (25%)
- Safe headroom to avoid OOM

---

### Issue 2: Redis - Insufficient Memory for 100-User Load 🔴

**Current:**
```bash
redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
```

**Problem:**
- 100 concurrent users
- Each velocity check stores: card_hash + timestamp + counter (~100 bytes)
- High-velocity scenario: 10K unique cards/hour = 1MB
- **But:** Redis also stores:
  - Redis Streams outbox (AUTH decisions waiting for monitoring worker)
  - Connection overhead (20 connections × ~10KB = 200KB)
  - Internal data structures

**Current usage estimate:**
- Velocity data: ~5MB
- Outbox stream (100 users × 2s avg = 50 msgs/s × 60s = 3K messages × 2KB = **6MB**)
- Connections: 200KB
- **Total: ~11MB** (under 256MB limit) ✅

**But at scale (1000 users):**
- Outbox: 500 msgs/s × 60s = 30K messages × 2KB = **60MB**
- Would exceed 256MB → evictions start → data loss

**Recommendation for current testing:**
- 256MB is **OK for 100 users** ✅
- For production (1000+ users): Increase to **512MB-1GB**

---

### Issue 3: No CPU Limits - Resource Contention ⚠️

**Current:** Only Redpanda has CPU limit (1 core)

**Problem:**
All containers compete for host CPU:
- Rule Engine (Java, CPU-intensive)
- PostgreSQL (if queried)
- MinIO (if uploading rulesets)
- Redis (single-threaded but can saturate 1 core)

**Impact:**
- Under 100-user load, Rule Engine needs **2-4 cores** for optimal performance
- Without limits, it steals CPU from Redis → Redis latency spikes → P95/P99 degradation

**Fix Required:**
```yaml
# docker-compose.apps.yml
rule-engine:
  deploy:
    resources:
      limits:
        cpus: '4'       # Max 4 cores
        memory: 2G
      reservations:
        cpus: '2'       # Guaranteed 2 cores
        memory: 1G
```

---

### Issue 4: PostgreSQL & MinIO - Unbounded Resources 🟡

**Current:** No limits

**Risk:**
- If rule-management uploads large rulesets during load test → MinIO spikes
- If analytics queries run → PostgreSQL spikes
- **Both steal resources from Rule Engine**

**Fix for Load Testing:**
```yaml
postgres:
  deploy:
    resources:
      limits:
        cpus: '1'
        memory: 512M
      reservations:
        cpus: '0.5'
        memory: 256M

minio:
  deploy:
    resources:
      limits:
        cpus: '1'
        memory: 512M
      reservations:
        cpus: '0.5'
        memory: 256M
```

---

## Optimal Pool Sizes Based on Container Capacity

### Formula: Pool Size = f(Memory, CPU, Concurrency)

**Redis Connection Pool:**

Formula:
```
Max Connections = (Container Memory - Overhead) / Per-Connection Memory
Per-Connection Memory ≈ 10KB (TCP buffers + Redis client state)
Redis Container Memory = 256MB
Overhead (Redis internal) = ~50MB

Max = (256MB - 50MB) / 10KB = ~20,000 connections (theoretical)
```

**BUT:** Redis is single-threaded! More connections ≠ better performance.

**Optimal for 100 users:**
```
Optimal Pool Size = Concurrent Users × 0.2 to 0.5
                  = 100 × 0.2 to 0.5
                  = 20 to 50 connections
```

**Current: 20** ✅ (conservative, good starting point)

**Recommendation:**
- Keep at **20** for now (matches current testing)
- Test with **50** if P95 improves (more parallel Redis ops)
- Don't exceed **100** (diminishing returns, connection overhead)

---

**Worker Thread Pool:**

Formula:
```
Optimal Threads = CPU Cores × (1 + Wait Time / CPU Time)
                = CPU Cores × (1 + Blocking Ratio)

For I/O-bound work (Redis XADD blocks):
  Blocking Ratio = Redis I/O Time / CPU Time
                 = 3ms / 3ms = 1.0

Optimal = 4 cores × (1 + 1.0) = 8 threads (too low!)

For mixed workload (80% I/O, 20% CPU):
  Blocking Ratio = 0.8 / 0.2 = 4.0
  Optimal = 4 cores × (1 + 4.0) = 20 threads ✅
```

**Current: 20** ✅ (good for 4-core allocation)

**But:** Rule Engine has **NO CPU limit** currently!

**With 2-core guarantee:**
```
Optimal = 2 cores × (1 + 4.0) = 10 threads
```

**With 4-core limit:**
```
Optimal = 4 cores × (1 + 4.0) = 20 threads ✅
```

**Recommendation:**
1. Add CPU limit: `cpus: '4'` (reserve 2, limit 4)
2. Keep worker threads at **20**
3. Test with **30** if P95 improves (more concurrency)
4. Monitor CPU usage (should stay under 80%)

---

**Redis Max Waiting Handlers:**

Formula:
```
Max Waiting = Concurrent Users + Buffer
            = 100 + 20% = 120
```

**Current: 100** ✅ (matches concurrent users)

**Recommendation:**
- Increase to **150** (50% buffer for burst traffic)
- This is just a queue, doesn't consume resources until used

---

## Host Resource Requirements

### Minimum for 100-User Load Test

| Resource | Minimum | Recommended | Notes |
|----------|---------|-------------|-------|
| **CPU** | 6 cores | **8 cores** | Rule Engine (4) + Redis (1) + Redpanda (1) + Postgres (1) + MinIO (1) |
| **Memory** | 5GB | **8GB** | Rule Engine (2G) + Redis (256M) + Redpanda (1G) + Postgres (512M) + MinIO (512M) + OS (2G) |
| **Disk I/O** | SSD | **NVMe SSD** | MinIO + Postgres + Redis AOF persistence |
| **Network** | 1Gbps | **1Gbps** | Docker bridge networking |

**Your host specs (check with):**
```bash
# CPU cores
nproc

# Total memory
free -h

# Disk type
lsblk -o NAME,TYPE,SIZE,MOUNTPOINT,FSTYPE,MODEL
```

---

## Recommended Configuration Changes

### 1. Rule Engine - Add JVM Heap + CPU Limits

```yaml
# docker-compose.apps.yml
rule-engine:
  deploy:
    resources:
      limits:
        cpus: '4'         # NEW: Limit to 4 cores
        memory: 2G        # EXISTING
      reservations:
        cpus: '2'         # NEW: Guarantee 2 cores
        memory: 1G        # EXISTING
  environment:
    # NEW: Set JVM heap to 75% of container memory
    - JAVA_OPTS=-Xms1G -Xmx1536M -XX:+UseG1GC -XX:MaxGCPauseMillis=200 -XX:+AlwaysPreTouch
    # EXISTING vars...
```

**Rationale:**
- 4-core limit prevents Rule Engine from starving other containers
- 2-core reservation guarantees baseline performance
- 1.5GB heap (75% of 2GB) leaves 512MB for non-heap (MetaSpace, threads, buffers)
- G1GC with 200ms pause target for consistent latency

---

### 2. Redis - Add CPU Limit (Keep Memory at 256MB)

```yaml
# docker-compose.yml
redis:
  deploy:
    resources:
      limits:
        cpus: '2'         # NEW: Redis can use up to 2 cores (for I/O)
        memory: 256M      # NEW: Make it explicit
      reservations:
        cpus: '1'         # NEW: Guarantee 1 core
        memory: 256M      # NEW
  command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
```

**Rationale:**
- Redis is single-threaded for commands, but uses extra threads for:
  - AOF persistence (disk I/O)
  - Client I/O (network threads)
- 2-core limit allows these background tasks without starving other containers

---

### 3. PostgreSQL & MinIO - Add Limits to Prevent Interference

```yaml
# docker-compose.yml
postgres:
  deploy:
    resources:
      limits:
        cpus: '1'
        memory: 512M
      reservations:
        cpus: '0.5'
        memory: 256M

minio:
  deploy:
    resources:
      limits:
        cpus: '1'
        memory: 512M
      reservations:
        cpus: '0.5'
        memory: 256M
```

**Rationale:**
- Load tests don't heavily use PostgreSQL or MinIO
- Limits prevent them from stealing resources if accidentally hit
- Reservations ensure they stay healthy

---

### 4. Redpanda - Increase Memory (Optional)

```yaml
# docker-compose.yml
redpanda:
  command: >
    # ... existing flags ...
    --memory 2G          # CHANGE: Was 1G
```

**Rationale:**
- At 100 users with MONITORING publishing, Kafka can buffer significant data
- 2GB gives more headroom for message buffering
- Won't help AUTH latency, but prevents Kafka backpressure

---

## Updated Pool Size Recommendations

### After Adding Resource Limits

| Pool | Current | Recommended | Rationale |
|------|---------|-------------|-----------|
| **Redis Pool** | 20 | **30** | With 2-core Redis limit, can handle more parallel connections |
| **Worker Threads** | 20 | **20** | Matches 4-core Rule Engine limit (4 × 5 = 20 for 80% I/O) |
| **Max Waiting Handlers** | 100 | **150** | 50% buffer for burst traffic |

### Test Matrix

| Test | Redis Pool | Workers | CPU Limit | Expected P50 | Expected P95 |
|------|-----------|---------|-----------|--------------|--------------|
| **Baseline** | 20 | 20 | None | 110ms | 320ms |
| **Test 1: +CPU Limit** | 20 | 20 | 4 cores | 100ms | 280ms |
| **Test 2: +Redis Pool** | 30 | 20 | 4 cores | 95ms | 250ms |
| **Test 3: +Workers** | 30 | 30 | 4 cores | 90ms | 220ms |

**Hypothesis:**
- Adding CPU limits will **reduce P95 by 15%** (less contention)
- Increasing Redis pool to 30 will **reduce P95 by another 10%** (more parallel Redis ops)
- Increasing workers to 30 will **reduce P95 by another 10%** (less queueing)

**Total expected:** P95: 320ms → ~220ms (~30% improvement)

---

## Implementation Steps

### Step 1: Update docker-compose Files

1. Update `docker-compose.yml`:
   - Add resource limits to Redis, PostgreSQL, MinIO
   - Increase Redpanda memory to 2G

2. Update `docker-compose.apps.yml`:
   - Add CPU limits to Rule Engine (4 cores limit, 2 cores reserved)
   - Add JAVA_OPTS for heap sizing

### Step 2: Rebuild and Restart

```bash
cd /c/Users/kanna/github/card-fraud-platform

# Stop all
doppler run -- docker compose -f docker-compose.yml -f docker-compose.apps.yml --profile apps down

# Rebuild rule-engine with changes
doppler run -- docker compose -f docker-compose.yml -f docker-compose.apps.yml build rule-engine

# Start infra + apps
doppler run -- docker compose -f docker-compose.yml -f docker-compose.apps.yml --profile apps up -d

# Wait for health
docker ps
```

### Step 3: Verify Resource Limits

```bash
# Check rule-engine limits
docker inspect card-fraud-rule-engine | grep -A 10 Resources

# Check Redis limits
docker inspect card-fraud-redis | grep -A 10 Resources

# Check memory usage during load test
docker stats --no-stream

# Check CPU usage during load test
docker stats
```

### Step 4: Run Load Test with JFR

```bash
# In rule-engine container, JFR will capture:
# - CPU usage per container
# - Thread pool stats
# - GC pauses
# - Redis I/O wait times

cd /c/Users/kanna/github/card-fraud-e2e-load-testing
```

### Step 5: Analyze Results

1. Compare P50/P95/P99 before/after
2. Check `docker stats` output during test
3. Analyze JFR recording for bottlenecks
4. Adjust pool sizes based on data

---

## Current Status Summary

### What's Good ✅

1. **Redis pool (20)** - Reasonable starting point
2. **Worker threads (20)** - Matches 4-core workload
3. **Rule Engine memory (2GB)** - Sufficient for 100 users
4. **Redis memory (256MB)** - OK for current testing

### What's Missing ❌

1. **No CPU limits** - Containers compete, unpredictable performance
2. **No JVM heap config** - Risk of OOM
3. **No resource reservations** - No guaranteed baseline
4. **No monitoring** - Can't see CPU/memory during tests

### What's Next 🎯

1. **Add resource limits** (30 min)
2. **Run baseline test** with limits (10 min)
3. **Compare before/after** (5 min)
4. **Tune pool sizes** based on data (1 hour)
5. **JFR analysis** to find remaining bottlenecks (30 min)

---

## Files to Modify

1. `C:\Users\kanna\github\card-fraud-platform\docker-compose.yml`
   - Add resource limits to Redis, PostgreSQL, MinIO, Redpanda

2. `C:\Users\kanna\github\card-fraud-platform\docker-compose.apps.yml`
   - Add CPU limits and JAVA_OPTS to rule-engine

3. `C:\Users\kanna\github\card-fraud-rule-engine\src\main\resources\application.yaml`
   - Update pool sizes after testing (Redis pool, worker threads)

---

**Next Action:** Implement resource limits and re-run load test to establish new baseline.
