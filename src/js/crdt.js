import crypto from "node:crypto";
import zlib from "node:zlib";

/**
 * CRDT LWW-Element-Set (Last-Write-Wins Element Set).
 * Résolution décentralisée et sans conflit des ajouts, révocations et expirations.
 */
export class LwwElementSet {
    constructor() {
        this.elements = new Map();
    }

    add(key, timestamp, ttlMs = 0) {
        const existing = this.elements.get(key);
        if (!existing) {
            this.elements.set(key, {
                key,
                addTs: Number(timestamp),
                remTs: 0,
                ttlMs: Number(ttlMs)
            });
        } else if (Number(timestamp) > existing.addTs) {
            existing.addTs = Number(timestamp);
            existing.ttlMs = Number(ttlMs);
        }
    }

    remove(key, timestamp) {
        const existing = this.elements.get(key);
        if (!existing) {
            this.elements.set(key, {
                key,
                addTs: 0,
                remTs: Number(timestamp),
                ttlMs: 0
            });
        } else if (Number(timestamp) > existing.remTs) {
            existing.remTs = Number(timestamp);
        }
    }

    contains(key, now = Date.now()) {
        const rec = this.elements.get(key);
        if (!rec) return false;
        if (rec.addTs <= rec.remTs) return false;
        return rec.ttlMs <= 0 || (now < rec.addTs + rec.ttlMs);
    }

    getActiveElements(now = Date.now()) {
        const active = [];
        for (const [key, rec] of this.elements.entries()) {
            if (rec.addTs > rec.remTs && (rec.ttlMs <= 0 || now < rec.addTs + rec.ttlMs)) {
                active.push(key);
            }
        }
        return active;
    }

    exportDelta() {
        return Array.from(this.elements.values());
    }

    mergeDelta(delta) {
        if (!Array.isArray(delta)) return;
        for (const entry of delta) {
            if (!entry || !entry.key) continue;
            const key = entry.key;
            const addTs = Number(entry.addTs || 0);
            const remTs = Number(entry.remTs || 0);
            const ttlMs = Number(entry.ttlMs || 0);
            const existing = this.elements.get(key);
            if (!existing) {
                this.elements.set(key, { key, addTs, remTs, ttlMs });
            } else {
                if (addTs > existing.addTs) {
                    existing.addTs = addTs;
                    existing.ttlMs = ttlMs;
                }
                if (remTs > existing.remTs) {
                    existing.remTs = remTs;
                }
            }
        }
    }

    pruneExpired(now = Date.now(), maxTombstoneAgeMs = 7 * 86400 * 1000) {
        for (const [key, rec] of this.elements.entries()) {
            const isExpired = rec.ttlMs > 0 && (now >= rec.addTs + rec.ttlMs);
            const isOldTombstone = rec.remTs > 0 && (now - rec.remTs > maxTombstoneAgeMs);
            if (isExpired || isOldTombstone) {
                this.elements.delete(key);
            }
        }
    }

    get size() {
        return this.elements.size;
    }
}

/**
 * Filtre de Bloom à double hachage SHA-256 avec compression Zlib.
 * Réduit l'empreinte de synchronisation inter-nœuds de plus de 90%.
 */
export class BloomFilterSync {
    constructor(bitSize, numHashFunctions, rawBuffer = null) {
        this.bitSize = Math.max(64, bitSize);
        this.numHashFunctions = Math.max(1, numHashFunctions);
        const byteLength = Math.ceil(this.bitSize / 8);
        this.buffer = rawBuffer ? Buffer.from(rawBuffer) : Buffer.alloc(byteLength);
    }

    static create(expectedElements = 1000, fpRate = 0.01) {
        const n = Math.max(10, expectedElements);
        const bitSize = Math.max(64, Math.ceil(-n * Math.log(fpRate) / (Math.LN2 ** 2)));
        const numHashes = Math.max(1, Math.round((bitSize / n) * Math.LN2));
        return new BloomFilterSync(bitSize, numHashes);
    }

    _hashItem(item) {
        const digest = crypto.createHash("sha256").update(String(item), "utf8").digest();
        const h1 = digest.readBigInt64BE(0);
        const h2 = digest.readBigInt64BE(8);
        const bitSizeBig = BigInt(this.bitSize);
        const indices = [];
        for (let i = 0; i < this.numHashFunctions; i++) {
            let combined = (h1 + BigInt(i) * h2) % bitSizeBig;
            if (combined < 0n) combined += bitSizeBig;
            indices.push(Number(combined));
        }
        return indices;
    }

    put(item) {
        for (const idx of this._hashItem(item)) {
            this.buffer[Math.floor(idx / 8)] |= (1 << (idx % 8));
        }
    }

    mightContain(item) {
        for (const idx of this._hashItem(item)) {
            if ((this.buffer[Math.floor(idx / 8)] & (1 << (idx % 8))) === 0) {
                return false;
            }
        }
        return true;
    }

    exportCompressedBase64() {
        const compressed = zlib.deflateSync(this.buffer, { level: 9 });
        return compressed.toString("base64url");
    }

    static fromCompressedBase64(b64Str, bitSize, numHashFunctions) {
        const compressed = Buffer.from(b64Str, "base64url");
        const decompressed = zlib.inflateSync(compressed);
        return new BloomFilterSync(bitSize, numHashFunctions, decompressed);
    }

    computeMissingDelta(localCrdtSet, now = Date.now()) {
        const delta = localCrdtSet.exportDelta();
        return delta.filter(entry => entry.key && !this.mightContain(entry.key));
    }
}