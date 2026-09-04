/**
 * @file Creates a store adapter for MongoDB.
 * This adapter uses a collection as a key-value store and leverages MongoDB's TTL indexes
 * for automatic expiration of documents.
 */

/**
 * Creates a store adapter for a MongoDB collection.
 * It's recommended to pass the `db` object and let the adapter handle the collection.
 *
 * **Note:** For TTL to work, you must create a TTL index on the `expiresAt` field in your collection.
 * In the mongo shell, run:
 * `db.yourCollectionName.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 })`
 *
 * @param {import('mongodb').Db} db - An instance of a MongoDB Db object.
 * @param {string} [collectionName='fingerprint_store'] - The name of the collection to use.
 * @returns {import('./fingerprint.js').IStore} An object that complies with the IStore interface.
 */
export function createMongoDbStore(db, collectionName = 'fingerprint_store') {
  const collection = db.collection(collectionName);
  
  // Custom replacer/reviver to handle Set serialization (identical to Redis/SQL stores)
  const replacer = (k, v) => (v instanceof Set ? Array.from(v) : v);
  const reviver = (k, v) => (k === 'ips' && Array.isArray(v) ? new Set(v) : v);

  return {
    async get(key) {
      const doc = await collection.findOne({ _id: key });
      if (!doc) return null;

      // Active expiration check to bypass eventual consistency of MongoDB's 60s TTL cleanup daemon
      if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
        await this.delete(key);
        return null;
      }

      try {
        return JSON.parse(doc.value, reviver);
      } catch (e) {
        // Fallback for legacy un-serialized raw values
        return doc.value;
      }
    },
    async set(key, value, ttl) {
      const stringValue = JSON.stringify(value, replacer);
      const doc = {
        _id: key,
        value: stringValue,
      };

      if (ttl && ttl > 0) {
        // Set the expiration date for the TTL index.
        doc.expiresAt = new Date(Date.now() + ttl * 1000);
      }

      await collection.updateOne(
        { _id: key },
        { $set: doc },
        { upsert: true }
      );
    },
    async has(key) {
      const doc = await collection.findOne({ _id: key }, { projection: { expiresAt: 1 } });
      if (!doc) return false;

      if (doc.expiresAt && new Date(doc.expiresAt) < new Date()) {
        await this.delete(key);
        return false;
      }
      return true;
    },
    async delete(key) {
      await collection.deleteOne({ _id: key });
    },
    async init() {
      // Automates index configuration
      await collection.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 });
    }
  };
}