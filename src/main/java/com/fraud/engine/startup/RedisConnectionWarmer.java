package com.fraud.engine.startup;

import io.quarkus.redis.datasource.RedisDataSource;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Warms up the Redis connection pool at application startup.
 * <p>
 * Pre-creates connections to eliminate cold-start latency on first requests.
 * Without warmup, the first Redis operation can take 200-300ms while
 * subsequent operations are 2-6ms.
 */
@ApplicationScoped
public class RedisConnectionWarmer {

    private static final Logger LOG = Logger.getLogger(RedisConnectionWarmer.class);

    @Inject
    RedisDataSource redisDataSource;

    @ConfigProperty(name = "quarkus.redis.max-pool-size", defaultValue = "100")
    int maxPoolSize;

    void onStart(@Observes StartupEvent event) {
        long startTime = System.currentTimeMillis();
        LOG.info("Warming up Redis connection pool...");

        int warmedConnections = 0;
        int targetConnections = Math.min(maxPoolSize, 50); // Warm up to 50 connections

        try {
            var commands = redisDataSource.value(String.class);
            
            // Pre-create connections by making lightweight PING commands
            for (int i = 0; i < targetConnections; i++) {
                try {
                    commands.get("_warmup_" + i); // Lightweight GET (key doesn't exist)
                    warmedConnections++;
                } catch (Exception e) {
                    LOG.warnf("Failed to warm connection %d: %s", i, e.getMessage());
                }
            }

            long duration = System.currentTimeMillis() - startTime;
            LOG.infof("Redis connection pool warmed: %d/%d connections in %dms", 
                     warmedConnections, targetConnections, duration);

        } catch (Exception e) {
            LOG.errorf(e, "Failed to warm up Redis connection pool");
        }
    }
}
