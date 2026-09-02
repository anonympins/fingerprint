import { describe, it, expect, beforeEach } from 'vitest';
import { __internal, configureStore } from '../src/js/fingerprint.js';

describe('IP Reputation Local System (Node.js)', () => {
    let mockStore;

    beforeEach(() => {
        mockStore = {
            _map: new Map(),
            async get(key) { return this._map.get(key); },
            async set(key, value) { this._map.set(key, value); },
            async has(key) { return this._map.has(key); },
            async delete(key) { this._map.delete(key); }
        };
        configureStore(mockStore);
    });

    it('should return a default score of 0 for unknown IPs', async () => {
        const score = await __internal.getIpReputationScore('1.1.1.1');
        expect(score).toBe(0);
    });

    it('should correctly increment and decrement score values', async () => {
        const ip = '192.168.1.1';
        await __internal.updateIpReputationScore(ip, 30);
        let score = await __internal.getIpReputationScore(ip);
        expect(score).toBe(30);

        await __internal.updateIpReputationScore(ip, -10);
        score = await __internal.getIpReputationScore(ip);
        expect(score).toBe(20);
    });

    it('should clamp the reputation score within bounds [0, 100]', async () => {
        const ip = '10.0.0.1';
        await __internal.updateIpReputationScore(ip, 150);
        let score = await __internal.getIpReputationScore(ip);
        expect(score).toBe(100);

        await __internal.updateIpReputationScore(ip, -200);
        score = await __internal.getIpReputationScore(ip);
        expect(score).toBe(0);
    });

    it('should apply passive decay of 2 points per hour of inactivity', async () => {
        const ip = '172.16.0.1';
        const now = Date.now();
        
        // Simulation d'un score de 50 mis à jour il y a 3 heures (3h * 2 points/heure = 6 points de perte)
        await mockStore.set(`ip-reputation:${ip}`, {
            score: 50,
            lastUpdate: now - (3 * 60 * 60 * 1000)
        });

        const score = await __internal.getIpReputationScore(ip);
        expect(score).toBe(44);
    });
});