-- Velocity Check Lua Script
-- Atomically increments a counter and sets expiry on first increment
-- Returns: [current_count, exceeded (1 or 0)]
--
-- KEYS[1] = velocity key
-- ARGV[1] = window_seconds (TTL)
-- ARGV[2] = threshold
--
-- This script ensures atomicity for velocity checking:
-- 1. Increments the counter
-- 2. Sets expiry on first increment (when count becomes 1)
-- 3. Returns count and whether threshold is exceeded

local key = KEYS[1]
local window_seconds = tonumber(ARGV[1])
local threshold = tonumber(ARGV[2])

-- Atomic increment
local count = redis.call('INCR', key)

-- Set expiry only on first increment
if count == 1 then
    redis.call('EXPIRE', key, window_seconds)
end

-- Return count and exceeded flag
local exceeded = 0
if count >= threshold then
    exceeded = 1
end

return {count, exceeded}
