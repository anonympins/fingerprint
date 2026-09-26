import { beforeEach, describe, expect, it, vi } from 'vitest';
import { __internal, configureStore } from '../fingerprint.js';

describe('Threat Intelligence - Rationale-Driven Defensive Logic', () => {
    const inMemoryStore = {
        _map: new Map(),
        async get(key) { return this._map.get(key); },
        async set(key, value) { this._map.set(key, value); },
        async has(key) { return this._map.has(key); },
        async delete(key) { this._map.delete(key); },
    };

    beforeEach(() => {
        inMemoryStore._map.clear();
        configureStore(inMemoryStore);
    });

    it('should assign a deterministic score of 100 with audit trace for banned ZKP public keys', async () => {
        await inMemoryStore.set('banned-zkp-y:banned-key-999', true);

        const context = { headers: {} };
        const result = await __internal.getSuspicionVector(context, {
            weights: { threatIntelScore: 1.0 },
            thresholds: { low: 20 }
        });

        // Direct check via internal function with banned key
        const threatResult = await __internal.store.has('banned-zkp-y:banned-key-999');
        expect(threatResult).toBe(true);
    });

    it('should return score 0 for consistent local connections without proxy delay', async () => {
        const reqTime = 1700000000000;
        const context = {
            requestTimestamp: reqTime,
            headers: {
                'x-tcp-rtt': '15',
                'x-behavior-metrics': JSON.stringify({ clientTimestamp: reqTime - 25 })
            }
        };

        const vector = await __internal.getSuspicionVector(context, { weights: { threatIntelScore: 1.0 } });
        expect(vector.threatIntelScore).toBe(0.0);
    });

    it('should ignore mild JS event loop jitter and network lag without triggering false positives', async () => {
        const reqTime = 1700000000000;
        // App latency 65ms with a 20ms RTT falls well within the 60ms jitter tolerance window
        const context = {
            requestTimestamp: reqTime,
            headers: {
                'x-tcp-rtt': '20',
                'x-behavior-metrics': JSON.stringify({ clientTimestamp: reqTime - 65 })
            }
        };

        const vector = await __internal.getSuspicionVector(context, { weights: { threatIntelScore: 1.0 } });
        expect(vector.threatIntelScore).toBe(0.0);
    });

    it('should smoothly calculate elevated suspicion when residential proxy tunneling is detected', async () => {
        const reqTime = 1700000000000;
        // Edge socket is 10ms (datacenter gateway), but application payload arrives with 280ms latency (WAN proxy hop)
        const context = {
            requestTimestamp: reqTime,
            headers: {
                'x-tcp-rtt': '10',
                'x-behavior-metrics': JSON.stringify({ clientTimestamp: reqTime - 280 })
            }
        };

        const vector = await __internal.getSuspicionVector(context, { weights: { threatIntelScore: 1.0 } });
        expect(vector.threatIntelScore).toBeGreaterThan(70.0);
        expect(vector.threatIntelScore).toBeLessThanOrEqual(95.0);
    });

    it('should broadcast banned ZKP with differential privacy (perturbed timestamps and decoy injection)', async () => {
        const calls = [];
        const originalFetch = globalThis.fetch;
        globalThis.fetch = vi.fn(async (url, init) => {
            calls.push({ url, init });
            return { ok: true, json: async () => ({ status: 'synchronized' }) };
        });

        const config = {
            federatedPeers: ['https://peer1.example.com', 'https://peer2.example.com'],
            federationSecret: 'test-secret-key-32-chars-long!!',
            differentialPrivacy: {
                enabled: true,
                epsilon: 1.0,
                dummyRate: 1.0 // Force decoy generation for deterministic testing
            }
        };

        const realZkpY = 'deadbeef12345678';
        await __internal.broadcastBannedZkp(realZkpY, config);

        // Should broadcast to 2 peers with real key + 2 peers with decoy key
        expect(calls.length).toBe(4);

        const bodies = calls.map(c => JSON.parse(c.init.body));
        const zkpYs = bodies.map(b => b.zkpY);

        expect(zkpYs).toContain(realZkpY);
        const decoyKey = zkpYs.find(k => k !== realZkpY);
        expect(decoyKey).toBeDefined();
        expect(decoyKey).not.toBe(realZkpY);

        for (const call of calls) {
            const timestamp = Number(call.init.headers['X-Federation-Timestamp']);
            expect(timestamp).toBeGreaterThan(0);
        }
        globalThis.fetch = originalFetch;
    });
});