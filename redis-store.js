import Redis from 'ioredis';

/**
 * @typedef {object} IStore
 * @property {(key: string) => Promise<any>} get
 * @property {(key: string, value: any, ttl?: number) => Promise<void>} set
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * Creates a Redis-based store implementation for the fingerprint library.
 * Requires the `ioredis` package.
 *
 * @param {string} redisUrl - The Redis connection URL (e.g., 'redis://localhost:6379').
 * @returns {IStore} An object implementing the IStore interface.
 */
export const createRedisStore = (redisUrl) => {
  const redis = new Redis(redisUrl);

  redis.on('error', (err) => {
    console.error('Redis Store Error:', err);
  });

  return {
    async get(key) {
      const data = await redis.get(key);
      return data ? JSON.parse(data) : null;
    },
    async set(key, value, ttl) {
      const serializedValue = JSON.stringify(value);
      if (ttl) {
        await redis.setex(key, ttl, serializedValue);
      } else {
        await redis.set(key, serializedValue);
      }
    },
    async has(key) {
      return (await redis.exists(key)) === 1;
    },
    async delete(key) {
      await redis.del(key);
    },
  };
};