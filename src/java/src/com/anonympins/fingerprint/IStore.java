package com.anonympins.fingerprint;

public interface IStore {
    Object get(String key);
    void set(String key, Object value, Integer ttl);
    boolean has(String key);
    void delete(String key);
    void clear();
}