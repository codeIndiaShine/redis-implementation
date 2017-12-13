package com.koala.rhschedule.util;

import org.springframework.stereotype.Component;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Protocol;

@Component
public class CacheUtil {

	public JedisPool jedisPool() {
		JedisPool pool = new JedisPool(new JedisPoolConfig(), "localhost", 6379, Protocol.DEFAULT_TIMEOUT, null);
		return pool;

	}

	public boolean addKeyValuePair(String key, String value) {

		Jedis jedis = null;

		try {
			jedis = jedisPool().getResource();

			jedis.set(key, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return jedis != null ? true : false;
	}

	public String getValueByKey(String key) {
		Jedis jedis = null;
		String value = null;
		try {
			jedis = jedisPool().getResource();

			value = jedis.get(key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return value;
	}
	
	public boolean keyExists(String key){
		Jedis jedis = null;
		try {
			jedis = jedisPool().getResource();
			return jedis.exists(key);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}
	
	public String replaceKey(String oldKey, String newKey){
		Jedis jedis = null;
		try {
			jedis = jedisPool().getResource();
			return jedis.rename(oldKey, newKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}