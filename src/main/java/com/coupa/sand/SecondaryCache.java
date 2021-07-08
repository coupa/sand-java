package com.coupa.sand;

import java.util.concurrent.TimeUnit;

import org.redisson.Redisson;
import org.redisson.api.LocalCachedMapOptions;
import org.redisson.api.LocalCachedMapOptions.CacheProvider;
import org.redisson.api.LocalCachedMapOptions.EvictionPolicy;
import org.redisson.api.LocalCachedMapOptions.ReconnectionStrategy;
import org.redisson.api.LocalCachedMapOptions.StoreMode;
import org.redisson.api.LocalCachedMapOptions.SyncStrategy;
import org.redisson.api.RLocalCachedMap;
import org.redisson.api.RedissonClient;
import org.redisson.config.Config;
import org.redisson.config.TransportMode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecondaryCache<K, V> {

	private static final Logger LOGGER = LoggerFactory.getLogger(SecondaryCache.class);
	
	private final RLocalCachedMap<K, V> localCachedMap;
	
	public static final String ENV_SAND_CACHE_REDIS_URL = "SAND_CACHE_REDIS_URL";
	public static final String ENV_SAND_CACHE_REDIS_PASSWORD = "ENV_SAND_CACHE_REDIS_PASSWORD";
	

	public SecondaryCache(String cacheName) {
		
		String password = System.getProperty(ENV_SAND_CACHE_REDIS_PASSWORD, null);
		
		Config config = new Config();
		
		config.useSingleServer()
				.setPassword(password)
				.setAddress(System.getProperty(ENV_SAND_CACHE_REDIS_URL, "redis://127.0.0.1:6379"));

		RedissonClient redisson = Redisson.create(config);
		
		LocalCachedMapOptions<K, V> cachedMapOptions = LocalCachedMapOptions.<K, V>defaults()
				.storeCacheMiss(false)
				.storeMode(StoreMode.LOCALCACHE_REDIS)
				.cacheProvider(CacheProvider.REDISSON)
				.evictionPolicy(EvictionPolicy.NONE)
				.cacheSize(10000)
				.reconnectionStrategy(ReconnectionStrategy.NONE)
				.syncStrategy(SyncStrategy.UPDATE)
				.timeToLive(10, TimeUnit.SECONDS)
				.maxIdle(10, TimeUnit.SECONDS);
		
		localCachedMap = redisson.getLocalCachedMap(cacheName, cachedMapOptions);
		
	}
	
	public V getValue(K key) {
		V value = localCachedMap.get(key);
		LOGGER.info("Cache {} - Get Value  {} = {}", localCachedMap.getName(), key, value);
		printCacheStats();
		return value;
	}
	
	public void putValue(K key, V value) {
		LOGGER.info("Cache {} - Put Value  {} = {}", localCachedMap.getName(), key, value);
		printCacheStats();
		localCachedMap.put(key, value);
		printCacheStats();
	}
	
	public void removeValue(K key) {
		printCacheStats();
		V value = localCachedMap.remove(key);
		LOGGER.info("Cache {} - Remove Value  {} = {}", localCachedMap.getName(), key, value);
		printCacheStats();
	}
	
	
	public void printCacheStats() {
		LOGGER.info("Cache {} - Cache Size {}", localCachedMap.getName(), localCachedMap.size());
	}
	
	

}
