/**
 * @file Creates a store adapter for Knex.js.
 * This adapter is compatible with various SQL databases like PostgreSQL, MySQL, and SQLite.
 * It handles serialization of complex objects and TTL for automatic data expiration.
 */

/**
 * Creates a store adapter for a Knex.js client.
 *
 * **Note:** You must create the table yourself before using the store.
 * The table should have at least the following columns:
 * - `key` (string, primary key)
 * - `value` (text or json/jsonb)
 * - `expiresAt` (datetime or timestamp with time zone)
 *
 * Example schema for PostgreSQL:
 * ```sql
 * CREATE TABLE your_table_name (
 *   "key" VARCHAR(255) PRIMARY KEY,
 *   "value" TEXT NOT NULL,
 *   "expiresAt" TIMESTAMPTZ
 * );
 * ```
 *
 * @param {import('knex').Knex} knex - An instance of the Knex client.
 * @param {string} [tableName='fingerprint_store'] - The name of the table to use.
 * @returns {import('./fingerprint.js').IStore} An object that complies with the IStore interface.
 */
export function createSqlStore(knex, tableName = 'fingerprint_store') {
  // Custom replacer/reviver to handle Set serialization, similar to the Redis store.
  const replacer = (k, v) => (v instanceof Set ? Array.from(v) : v);
  const reviver = (k, v) => (k === 'ips' && Array.isArray(v) ? new Set(v) : v);

  return {
    async get(key) {
      const row = await knex(tableName).where('key', key).first();
      if (!row) return null;

      // Manually check for expiration, as not all SQL databases have automatic TTL cleanup.
      if (row.expiresAt && new Date(row.expiresAt) < new Date()) {
        await this.delete(key); // Clean up expired key.
        return null;
      }

      try {
        return JSON.parse(row.value, reviver);
      } catch (e) {
        // In case of malformed JSON, treat it as a miss.
        return null;
      }
    },

    async set(key, value, ttl) {
      const stringValue = JSON.stringify(value, replacer);
      const expiresAt = ttl ? new Date(Date.now() + ttl * 1000) : null;

      // Use native upsert capabilities of Knex for different SQL dialects.
      await knex(tableName)
        .insert({ key, value: stringValue, expiresAt })
        .onConflict('key')
        .merge();
    },

    async has(key) {
      const row = await knex(tableName).where('key', key).first('key');
      if (!row) return false;
      // Also check for expiration here.
      if (row.expiresAt && new Date(row.expiresAt) < new Date()) {
        return false;
      }
      return true;
    },

    async delete(key) {
      await knex(tableName).where('key', key).del();
    },
  };
}