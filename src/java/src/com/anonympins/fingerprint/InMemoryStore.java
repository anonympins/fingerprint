package com.anonympins.fingerprint;

import com.anonympins.fingerprint.utils.ChallengeUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryStore implements IStore {
    private static class StoreItem {
        final Object value;
        final Long expiresAt;

        StoreItem(Object value, Long expiresAt) {
            this.value = value;
            this.expiresAt = expiresAt;
        }

        boolean isExpired() {
            return expiresAt != null && expiresAt < System.currentTimeMillis();
        }
    }

    private final Map<String, StoreItem> data = new ConcurrentHashMap<>();

    public InMemoryStore() {
        ChallengeUtils.setStore(this);
    }

    @Override
    public Object get(String key) {
        StoreItem item = data.get(key);
        if (item == null) {
            return null;
        }
        if (item.isExpired()) {
            delete(key);
            return null;
        }
        return item.value;
    }

    @Override
    public void set(String key, Object value, Integer ttl) {
        Long expiresAt = ttl != null ? System.currentTimeMillis() + (ttl * 1000L) : null;
        data.put(key, new StoreItem(value, expiresAt));
    }

    @Override
    public boolean has(String key) {
        StoreItem item = data.get(key);
        if (item == null) {
            return false;
        }
        if (item.isExpired()) {
            delete(key);
            return false;
        }
        return true;
    }

    @Override
    public void delete(String key) {
        data.remove(key);
    }

    public void clear() {
        data.clear();
    }
}