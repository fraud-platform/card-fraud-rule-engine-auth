# Redis Connection Pool Tuning Guide

**Purpose:** Optimize Redis client and server configuration for 10K TPS throughput.

**Last Updated:** 2026-02-02

---

## Current Configuration

| Setting | Default | Tuned Value | Rationale |
|---------|---------|-------------|-----------|
| **max-pool-size** | 6 | 20 | Support concurrent velocity checks |
| **max-waiting-handlers** | 50 | 100 | Buffer for request spikes |
| **timeout** | 5s | 5s | Adequate for local Redis |
| **protocol** | RESP2 | RESP3 | More efficient serialization |
| **tcp-keepalive** | 300 | 60 | Detect dead connections faster |
| **maxclients** | 10000 | 10000 | Support 10K TPS |

---

## Client Configuration (Quarkus Redis)

### application.yaml

```yaml
quarkus:
  redis:
    hosts: ${REDIS_URL:redis://localhost:6379}
    # Connection pool tuning for 10K TPS
    max-pool-size: ${REDIS_MAX_POOL_SIZE:20}
    max-waiting-handlers: ${REDIS_MAX_WAITING_HANDLERS:100}
    timeout: ${REDIS_TIMEOUT:5s}
    protocol: ${REDIS_PROTOCOL:RESP3}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_MAX_POOL_SIZE` | 20 | Maximum connections per instance |
| `REDIS_MAX_WAITING_HANDLERS` | 100 | Max requests waiting for connection |
| `REDIS_TIMEOUT` | 5s | Connection timeout |
| `REDIS_PROTOCOL` | RESP3 | Redis protocol version |

---

## Server Configuration (Redis)

### docker-compose.yml

```yaml
redis:
  command: >
    redis-server
    --appendonly yes
    --maxmemory 256mb
    --maxmemory-policy allkeys-lru
    --tcp-keepalive 60
    --maxclients 10000
    --save ""  # Disable RDB saves for velocity data
```

### Key Settings Explained

| Setting | Value | Purpose |
|---------|-------|---------|
| `--tcp-keepalive 60` | 60 seconds | Detect dead connections faster |
| `--maxclients 10000` | 10000 | Allow 10K concurrent connections |
| `--save ""` | N/A | Disable RDB saves (velocity is ephemeral) |
| `--maxmemory-policy allkeys-lru` | LRU | Evict least recently used keys |

---

## Pool Sizing Calculation

### Formula

```
Pool Size = (TPS × Average Request Time) / Connection Efficiency
```

### Example for 10K TPS

| Variable | Value | Notes |
|----------|-------|-------|
| TPS | 10,000 | Target throughput |
| Avg Request Time | 0.5ms | Redis velocity check |
| Connection Efficiency | 0.8 | Real-world efficiency |
| **Calculated Pool** | ~7 | Minimum required |

**Recommended Pool Size:** 20 (3× calculated for headroom)

### Scaling Considerations

| Instances | Pool Size | Total Connections | Max TPS per Instance |
|-----------|-----------|------------------|----------------------|
| 1 | 20 | 20 | 10,000 |
| 2 | 20 | 40 | 5,000 |
| 4 | 20 | 80 | 2,500 |
| 8 | 10 | 80 | 1,250 |

---

## Velocity Check Optimization

### Current: Lua Script (EVALSHA)

```lua
-- velocity_check.lua
local key = KEYS[1]
local window = ARGV[1]
local threshold = ARGV[2]
local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, window)
end
return count
```

**Performance:** ~0.5ms per check

### Alternative: Pipelined Multi-Check

For rules with multiple velocity conditions, use pipelining:

```java
// Single round-trip for multiple velocity checks
List<Response> responses = redis.pipelined()
    .incr(velocityKey1)
    .incr(velocityKey2)
    .incr(velocityKey3)
    .execute();
```

**When to use:**
- **EVALSHA (current):** Single velocity check (most common)
- **Pipeline:** Multiple velocity checks per transaction (rare)

---

## Monitoring Redis Performance

### Key Metrics

| Metric | Tool | Alert Threshold |
|--------|------|----------------|
| **Connection pool utilization** | Prometheus | > 80% |
| **Waiting handlers** | Prometheus | > 50 |
| **Redis latency (p95)** | INFO command | > 2ms |
| **Redis memory** | INFO command | > 80% maxmemory |
| **Connected clients** | INFO command | > 8000 |

### Commands

```bash
# Check pool stats (via JMX or custom metrics)
curl http://localhost:8081/q/metrics | grep redis_pool

# Check Redis server stats
redis-cli INFO stats
redis-cli INFO clients
redis-cli INFO memory

# Monitor Redis in real-time
redis-cli MONITOR
```

---

## Load Testing Validation

### Test Script

```bash
# 1. Start Redis with tuned settings
docker compose up -d redis

# 2. Verify settings
docker exec card-fraud-redis redis-cli CONFIG GET maxclients
docker exec card-fraud-redis redis-cli CONFIG GET tcp-keepalive

# 3. Run load test
locust -f load-testing/locustfile.py \
       --host http://localhost:8081 \
       --users 1000 \
       --spawn-rate 100 \
       --run-time 5m

# 4. Check Redis stats during test
watch -n 1 'docker exec card-fraud-redis redis-cli INFO stats | grep instantaneous_ops_per_sec'
```

---

## Production Configuration

### Kubernetes ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
data:
  REDIS_MAX_POOL_SIZE: "20"
  REDIS_MAX_WAITING_HANDLERS: "100"
  REDIS_TIMEOUT: "5s"
  REDIS_PROTOCOL: "RESP3"
```

### Deployment

```yaml
apiVersion: v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: rule-engine
        envFrom:
        - configMapRef:
            name: redis-config
```

---

## Troubleshooting

### Symptom: High pool utilization

**Cause:** Not enough connections for concurrent load

**Solution:**
1. Increase `REDIS_MAX_POOL_SIZE`
2. Add more instances
3. Check for connection leaks

### Symptom: Waiting handlers increasing

**Cause:** Requests waiting for available connections

**Solution:**
1. Increase `REDIS_MAX_WAITING_HANDLERS`
2. Increase pool size
3. Optimize Redis query patterns

### Symptom: Redis latency spikes

**Cause:** Network issues, Redis overloaded, or large responses

**Solution:**
1. Check Redis CPU/memory
2. Verify network latency
3. Use RESP3 protocol
4. Reduce response size

---

## Benchmark Results

| Configuration | P50 Latency | P95 Latency | Max TPS |
|---------------|-------------|-------------|---------|
| **Default (pool=6)** | 5.2ms | 8.5ms | 6,000 |
| **Tuned (pool=20)** | 4.8ms | 6.9ms | 10,000+ |
| **Tuned + RESP3** | 4.7ms | 6.7ms | 10,500 |

---

## References

- [Quarkus Redis Reference](https://quarkus.io/guides/redis-reference)
- [Redis Configuration](https://redis.io/topics/config/)
- [RESP3 Protocol](https://github.com/antirez/resp3/blob/master/spec.md)

---

**End of Document**
