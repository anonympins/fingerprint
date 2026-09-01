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
  return {
    async get(key) {
      const value = await redisClient.get(key);
      if (!value) return null;
      // Use a reviver to convert arrays back to Sets for specific keys like 'ips'.
      return JSON.parse(value, (k, v) => {
        if (k === 'ips' && Array.isArray(v)) {
          return new Set(v);
        }
        return v;
      });
    },
    async set(key, value, ttl) {
      // Use a replacer to convert Set objects into arrays before serialization.
      const stringValue = JSON.stringify(value, (k, v) => {
        if (v instanceof Set) {
          return Array.from(v);
        }
        return v;
      });

      if (ttl && ttl > 0) {
        await redisClient.set(key, stringValue, 'EX', ttl);
      } else {
        await redisClient.set(key, stringValue);
      }
    },
    async has(key) { return (await redisClient.exists(key)) === 1; },
    async delete(key) { await redisClient.del(key); },
  };
}