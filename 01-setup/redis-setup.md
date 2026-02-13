# Local Redis Setup Guide

This guide covers setting up and using Redis for the **card-fraud-rule-engine** project.

## Overview

Redis 8.4 is used for:
- **Velocity counters** - Atomic transaction counting per dimension
- **Hot reload signals** - Ruleset version tracking and change notifications

## Docker vs Native Installation

### Docker (Recommended for Development)

This project uses Docker Compose for local development:

```powershell
# Start Redis (and Redpanda)
uv run infra-local-up

# Start Redis only
uv run redis-local-up
```

### Native Redis Installation

If you prefer to install Redis natively:

**Windows:**
- Download Redis for Windows from [GitHub releases](https://github.com/tporadowski/redis/releases)
- Or use WSL2 to run Linux version

**macOS:**
```bash
brew install redis
brew services start redis
```

**Linux:**
```bash
sudo apt-get install redis-server  # Ubuntu/Debian
sudo systemctl start redis        # Start service
```

## Quick Commands

```powershell
# Start Redis (and Redpanda)
uv run infra-local-up

# Start Redis only
uv run redis-local-up

# Verify Redis is working
uv run redis-local-verify

# Stop Redis
uv run redis-local-down

# Stop all infrastructure (Redis + Redpanda)
uv run infra-local-down

# Reset Redis (stop + remove data)
uv run redis-local-reset
```

## Docker Compose Configuration

The `docker-compose.yml` file defines:

```yaml
services:
  redis:
    image: redis:8.4-alpine
    container_name: card-fraud-rule-engine-redis
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    command: redis-server --appendonly yes --maxmemory 256mb --maxmemory-policy allkeys-lru
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
```

### Redis Configuration Notes

| Setting | Value | Purpose |
|---------|-------|---------|
| `image` | `redis:8.4-alpine` | Redis 8.4 with Alpine Linux |
| `appendonly yes` | AOF persistence | Data durability |
| `maxmemory` | `256mb` | Memory limit |
| `maxmemory-policy` | `allkeys-lru` | Eviction policy |

## Connection String

The Redis connection string is managed by Doppler:

```properties
REDIS_URL=redis://localhost:6379
```

## Velocity Key Format

Keys follow this pattern:

```
vel:{ruleset_key}:{rule_id}:{dimension}:{encoded_value}
```

Examples:
- `vel:CARD_AUTH:rule-001:card_hash:abc123...`
- `vel:CARD_AUTH:rule-002:amount:100-200`
- `vel:CARD_MONITORING:rule-001:card_hash:xyz789...`

## Health Check

Verify Redis is running:

```powershell
uv run redis-local-verify
```

Expected output:
```
[1/2] Checking Redis container status...
[OK] Redis container is running

[2/2] Testing Redis connection...
[OK] Redis PING successful
   redis_version:7.2.4
   os:Linux 6.5.0...

============================================================
REDIS SETUP VERIFIED
============================================================
Endpoint: redis://localhost:6379

Next steps:
  - Start dev server: uv run doppler-local
  - Run tests: uv run doppler-local-test
  - Stop Redis: uv run redis-local-down
```

## Manual Commands

If you need to run Redis commands manually:

```powershell
# Connect to Redis CLI
docker exec -it card-fraud-rule-engine-redis redis-cli

# Native Redis (if not using Docker)
redis-cli

# Check all velocity keys
KEYS vel:*

# Check a specific counter
GET vel:CARD_AUTH:rule-001:card_hash:abc123

# Check counter value and TTL
GET vel:CARD_AUTH:rule-001:card_hash:abc123
TTL vel:CARD_AUTH:rule-001:card_hash:abc123

# Increment a counter (testing)
INCR vel:CARD_AUTH:rule-001:card_hash:abc123

# Set TTL (in seconds)
EXPIRE vel:CARD_AUTH:rule-001:card_hash:abc123 3600

# Monitor commands in real-time (great for debugging)
MONITOR

# Check server info
INFO server
INFO memory
INFO stats

# Flush all data (development only!)
FLUSHALL

# Flush only velocity keys (development only!)
--eval 'return redis.call("DEL", unpack(redis.call("KEYS", "vel:*")))'
```

## Debugging Velocity Counters

### View All Velocity Keys

```powershell
docker exec -it card-fraud-rule-engine-redis redis-cli
> KEYS vel:*
```

### Check Specific Velocity Pattern

```powershell
# All velocity for a specific card hash
docker exec -it card-fraud-rule-engine-redis redis-cli KEYS "vel:*:card_hash:*"

# All velocity for a specific ruleset
docker exec -it card-fraud-rule-engine-redis redis-cli KEYS "vel:CARD_AUTH:*"
```

### Inspect Velocity Counter Value

```powershell
# Get current count
docker exec -it card-fraud-rule-engine-redis redis-cli GET vel:CARD_AUTH:rule-001:card_hash:abc123

# Get time-to-live in seconds
docker exec -it card-fraud-rule-engine-redis redis-cli TTL vel:CARD_AUTH:rule-001:card_hash:abc123
```

### Reset State for Testing

```powershell
# Option 1: Reset only velocity keys (recommended)
docker exec card-fraud-rule-engine-redis redis-cli --scan --pattern "vel:*" | xargs docker exec card-fraud-rule-engine-redis redis-cli DEL

# Option 2: Flush all data (nuclear option)
uv run redis-local-reset
```

## Troubleshooting

### Issue: "Connection refused"

**Cause:** Redis container not running

**Fix:**
```powershell
uv run redis-local-up
```

### Issue: "OOM command not allowed"

**Cause:** Memory limit exceeded

**Fix:**
```powershell
# Check memory usage
docker exec card-fraud-rule-engine-redis redis-cli INFO memory

# Clear all velocity keys (development only)
docker exec card-fraud-rule-engine-redis redis-cli FLUSHALL
```

### Issue: Data persistence

Redis uses AOF (Append-Only File) persistence. To reset:

```powershell
uv run redis-local-reset
```

## Related Documentation

- [doppler-secrets-setup.md](doppler-secrets-setup.md) - Doppler configuration
- [AGENTS.md](../../AGENTS.md) - Agent instructions
