import { MongoClient } from 'mongodb';

/**
 * @typedef {object} IStore
 * @property {(key: string) => Promise<any>} get
 * @property {(key: string, value: any, ttl?: number) => Promise<void>} set
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * Creates a MongoDB-based store implementation for the fingerprint library.
 * Requires the `mongodb` package.
 *
 * This store uses a TTL index on the `expiresAt` field for automatic document cleanup.
 * Ensure the TTL index is created on your collection:
 * `db.collection('your_collection_name').createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 });`
 *
 * @param {string} mongoUri - The MongoDB connection URI (e.g., 'mongodb://localhost:27017').
 * @param {string} dbName - The name of the database to use.
 * @param {string} collectionName - The name of the collection to store data in.
 * @returns {IStore} An object implementing the IStore interface.
 */
export const createMongoStore = async (mongoUri, dbName, collectionName = 'fingerprint_store') => {
  const client = new MongoClient(mongoUri);
  let collection;

  try {
    await client.connect();
    const db = client.db(dbName);
    collection = db.collection(collectionName);

    // Ensure TTL index exists for automatic cleanup of temporary data (like secrets)
    // Documents without an expiresAt field will not be affected by this index.
    await collection.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 }).catch(err => {
      // Ignore if index already exists
      if (!err.message.includes('Index with name: expiresAt_1 already exists')) {
        console.warn('MongoDB Store: Could not create TTL index. Manual cleanup may be required for temporary data.', err);
      }
    });
    console.log(`MongoDB Store connected to ${dbName}.${collectionName} and TTL index ensured.`);
  } catch (error) {
    console.error('Failed to connect to MongoDB for fingerprint store:', error);
    throw error;
  }

  return {
    async get(key) {
      const doc = await collection.findOne({ _id: key, $or: [{ expiresAt: { $gt: new Date() } }, { expiresAt: null }] });
      return doc ? doc.value : null;
    },
    async set(key, value, ttl) {
      const expiresAt = ttl ? new Date(Date.now() + ttl * 1000) : null;
      await collection.updateOne({ _id: key }, { $set: { value, expiresAt } }, { upsert: true });
    },
    async has(key) {
      return (await collection.countDocuments({ _id: key, $or: [{ expiresAt: { $gt: new Date() } }, { expiresAt: null }] })) > 0;
    },
    async delete(key) {
      await collection.deleteOne({ _id: key });
    },
  };
};