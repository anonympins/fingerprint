package com.anonympins.fingerprint.crdt;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CRDT LWW-Element-Set (Last-Write-Wins Element Set) pour la Threat Intelligence.
 * Assure une convergence sans conflit pour les ajouts, révocations et expirations.
 */
public class LwwElementSet {

    public static class ElementRecord {
        private final String key;
        private volatile long addTimestamp;
        private volatile long removeTimestamp;
        private volatile long ttlMs;

        public ElementRecord(String key, long addTimestamp, long removeTimestamp, long ttlMs) {
            this.key = key;
            this.addTimestamp = addTimestamp;
            this.removeTimestamp = removeTimestamp;
            this.ttlMs = ttlMs;
        }

        public String getKey() { return key; }
        public long getAddTimestamp() { return addTimestamp; }
        public long getRemoveTimestamp() { return removeTimestamp; }
        public long getTtlMs() { return ttlMs; }

        public boolean isActive(long now) {
            if (addTimestamp <= removeTimestamp) {
                return false;
            }
            return ttlMs <= 0 || (now < addTimestamp + ttlMs);
        }

        public synchronized void merge(long otherAdd, long otherRemove, long otherTtl) {
            if (otherAdd > this.addTimestamp) {
                this.addTimestamp = otherAdd;
                this.ttlMs = otherTtl;
            }
            if (otherRemove > this.removeTimestamp) {
                this.removeTimestamp = otherRemove;
            }
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("key", key);
            map.put("addTs", addTimestamp);
            map.put("remTs", removeTimestamp);
            map.put("ttlMs", ttlMs);
            return map;
        }
    }

    private final Map<String, ElementRecord> elements = new ConcurrentHashMap<>();

    public void add(String key, long timestamp, long ttlMs) {
        elements.compute(key, (k, existing) -> {
            if (existing == null) {
                return new ElementRecord(key, timestamp, 0L, ttlMs);
            }
            existing.merge(timestamp, 0L, ttlMs);
            return existing;
        });
    }

    public void remove(String key, long timestamp) {
        elements.compute(key, (k, existing) -> {
            if (existing == null) {
                return new ElementRecord(key, 0L, timestamp, 0L);
            }
            existing.merge(0L, timestamp, existing.getTtlMs());
            return existing;
        });
    }

    public boolean contains(String key, long now) {
        ElementRecord rec = elements.get(key);
        return rec != null && rec.isActive(now);
    }

    public List<String> getActiveElements(long now) {
        List<String> active = new ArrayList<>();
        for (ElementRecord rec : elements.values()) {
            if (rec.isActive(now)) {
                active.add(rec.getKey());
            }
        }
        return active;
    }

    public List<Map<String, Object>> exportDelta() {
        List<Map<String, Object>> delta = new ArrayList<>();
        for (ElementRecord rec : elements.values()) {
            delta.add(rec.toMap());
        }
        return delta;
    }

    public void mergeDelta(List<Map<String, Object>> delta) {
        if (delta == null) return;
        for (Map<String, Object> entry : delta) {
            String key = (String) entry.get("key");
            long addTs = ((Number) entry.getOrDefault("addTs", 0L)).longValue();
            long remTs = ((Number) entry.getOrDefault("remTs", 0L)).longValue();
            long ttlMs = ((Number) entry.getOrDefault("ttlMs", 0L)).longValue();
            if (key != null) {
                elements.compute(key, (k, existing) -> {
                    if (existing == null) {
                        return new ElementRecord(key, addTs, remTs, ttlMs);
                    }
                    existing.merge(addTs, remTs, ttlMs);
                    return existing;
                });
            }
        }
    }

    public void pruneExpiredTombstones(long now, long maxTombstoneAgeMs) {
        elements.entrySet().removeIf(entry -> {
            ElementRecord rec = entry.getValue();
            boolean isExpired = rec.getTtlMs() > 0 && (now >= rec.getAddTimestamp() + rec.getTtlMs());
            boolean isOldTombstone = rec.getRemoveTimestamp() > 0 && (now - rec.getRemoveTimestamp() > maxTombstoneAgeMs);
            return isExpired || isOldTombstone;
        });
    }

    public int size() {
        return elements.size();
    }

    public void clear() {
        elements.clear();
    }
}