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

  return {
    async get(key) {
      const doc = await collection.findOne({ _id: key });
      // The TTL index automatically removes expired documents, so no need to check `expiresAt` here.
      return doc ? doc.value : null;
    },
    async set(key, value, ttl) {
      const doc = {
        _id: key,
        value: value,
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
      const count = await collection.countDocuments({ _id: key });
      return count > 0;
    },
    async delete(key) {
      await collection.deleteOne({ _id: key });
    },
  };
}