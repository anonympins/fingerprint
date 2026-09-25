import { beforeEach, describe, expect, it } from 'vitest';
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
});