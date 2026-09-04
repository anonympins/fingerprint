import {afterAll, beforeAll, beforeEach, describe, expect, it} from 'vitest';
import {createRedisStore} from '../src/js/redis-store.js';
import {createMongoDbStore} from '../src/js/mongodb-store.js';

// Helper function to wait for TTL expiration in tests
const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Common test suite for any store implementation
const runStoreTests = (storeFactory) => {
    let store;

    beforeAll(async () => {
        store = await storeFactory();
    });

    it('should set and get a simple value', async () => {
        await store.set('key1', 'value1');
        const value = await store.get('key1');
        expect(value).toBe('value1');
    });

    it('should return null for a non-existent key', async () => {
        const value = await store.get('non-existent-key');
        expect(value).toBeNull();
    });

    it('should correctly handle objects with Sets', async () => {
        const deviceData = {
            initialDeviceHash: 'hash123',
            ips: new Set(['1.1.1.1', '2.2.2.2']),
            lastUpdate: Date.now(),
        };
        await store.set('device:123', deviceData);
        const retrieved = await store.get('device:123');

        expect(retrieved).toBeInstanceOf(Object);
        expect(retrieved.ips).toBeInstanceOf(Set);
        expect(retrieved.ips.has('1.1.1.1')).toBe(true);
        expect(retrieved.ips.has('2.2.2.2')).toBe(true);
    });

    it('should delete a key', async () => {
        await store.set('key-to-delete', 'data');
        let value = await store.get('key-to-delete');
        expect(value).toBe('data');

        await store.delete('key-to-delete');
        value = await store.get('key-to-delete');
        expect(value).toBeNull();
    });

    it('should check if a key exists with has()', async () => {
        await store.set('existing-key', 'data');
        expect(await store.has('existing-key')).toBe(true);
        expect(await store.has('non-existing-key')).toBe(false);
    });

    it('should handle TTL correctly', async () => {
        await store.set('ttl-key', 'volatile data', 1); // 1 second TTL
        let value = await store.get('ttl-key');
        expect(value).toBe('volatile data');

        await sleep(1500); // Wait for TTL to expire

        value = await store.get('ttl-key');
        expect(value).toBeNull();
    });
};

// --- Redis Store Tests ---
// These tests will be skipped if REDIS_URL is not in the environment.
describe.runIf(process.env.REDIS_URL)('Redis Store', () => {
    let redisClient;

    const factory = async () => {
        const { default: Redis } = await import('ioredis');
        redisClient = new Redis(process.env.REDIS_URL);
        return createRedisStore(redisClient);
    };

    beforeEach(async () => {
        if (redisClient) await redisClient.flushdb();
    });

    afterAll(async () => {
        if (redisClient) await redisClient.quit();
    });

    runStoreTests(factory);
});

// --- MongoDB Store Tests ---
// These tests will be skipped if MONGODB_URL is not in the environment.
describe.runIf(process.env.MONGODB_URL)('MongoDB Store', () => {
    let mongoClient;
    let collection;

    const factory = async () => {
        const { MongoClient } = await import('mongodb');
        mongoClient = new MongoClient(process.env.MONGODB_URL);
        await mongoClient.connect();
        const db = mongoClient.db('fingerprint_test_db');
        const store = createMongoDbStore(db, 'store');
        await store.init();
        collection = db.collection('store');
        return store;
    };

    beforeEach(async () => {
        if (collection) await collection.deleteMany({});
    });

    afterAll(async () => {
        if (mongoClient) await mongoClient.close();
    });

    runStoreTests(factory);
});