/**
 * @file Creates a store adapter for ioredis.
 * This adapter handles the serialization and deserialization of complex objects,
 * including the conversion of Set objects to arrays for storage in Redis.
 */

/**
 * Creates a store adapter for an ioredis client.
 * @param {import('ioredis').Redis} redisClient - An instance of the ioredis client.
 * @returns {import('./fingerprint.js').IStore} An object that complies with the IStore interface.
 */
export function createRedisStore(redisClient) {
  const replacer = (k, v) => (v instanceof Set ? Array.from(v) : v);
  const reviver = (k, v) => (k === 'ips' && Array.isArray(v) ? new Set(v) : v);

  const localStore = new Map();
  const localTimeouts = new Map();
  let isDown = false;
  let reconnecting = false;

  const triggerFallback = () => {
    if (!isDown) {
      isDown = true;
      attemptReconnection();
    }
  };

  const attemptReconnection = () => {
    if (reconnecting) return;
    reconnecting = true;
    const interval = setInterval(async () => {
      try {
        await redisClient.ping();
        isDown = false;
        reconnecting = false;
        clearInterval(interval);
      } catch (err) {
        // Continue de tenter la reconnexion toutes les 5 secondes
      }
    }, 5000);
    if (interval.unref) interval.unref();
  };

  const setLocal = (key, value, ttl) => {
    localStore.set(key, value);
    if (localTimeouts.has(key)) {
      clearTimeout(localTimeouts.get(key));
    }
    if (ttl && ttl > 0) {
      const timeout = setTimeout(() => {
        localStore.delete(key);
        localTimeouts.delete(key);
      }, ttl * 1000);
      if (timeout.unref) timeout.unref();
      localTimeouts.set(key, timeout);
    }
  };

  return {
    async get(key) {
      if (isDown) {
        return localStore.get(key) || null;
      }
      try {
        const value = await redisClient.get(key);
        if (!value) return null;
        return JSON.parse(value, reviver);
      } catch (e) {
        triggerFallback();
        return localStore.get(key) || null;
      }
    },
    async set(key, value, ttl) {
      if (isDown) {
        setLocal(key, value, ttl);
        return;
      }
      try {
        const stringValue = JSON.stringify(value, replacer);
        if (ttl && ttl > 0) {
          await redisClient.set(key, stringValue, 'EX', ttl);
        } else {
          await redisClient.set(key, stringValue);
        }
      } catch (e) {
        triggerFallback();
        setLocal(key, value, ttl);
      }
    },
    async has(key) {
      if (isDown) {
        return localStore.has(key);
      }
      try {
        return (await redisClient.exists(key)) === 1;
      } catch (e) {
        triggerFallback();
        return localStore.has(key);
      }
    },
    async delete(key) {
      if (localTimeouts.has(key)) {
        clearTimeout(localTimeouts.get(key));
        localTimeouts.delete(key);
      }
      localStore.delete(key);
      if (isDown) return;
      try {
        await redisClient.del(key);
      } catch (e) {
        triggerFallback();
      }
    },
    async clear() {
      localStore.clear();
      for (const timeout of localTimeouts.values()) {
        clearTimeout(timeout);
      }
      localTimeouts.clear();
      if (isDown) return;
      try {
        await redisClient.flushdb();
      } catch (e) {
        triggerFallback();
      }
    }
  };
}