import { describe, expect, it, beforeEach } from 'vitest';
import { __internal } from '../fingerprint.js';

const { dnsCircuitBreaker, recordDnsSuccess, recordDnsFailure, canAttemptDns } = __internal;

describe('DNS Circuit Breaker', () => {
    beforeEach(() => {
        dnsCircuitBreaker.state = 'CLOSED';
        dnsCircuitBreaker.failureCount = 0;
        dnsCircuitBreaker.lastStateChange = 0;
        dnsCircuitBreaker.threshold = 5;
        dnsCircuitBreaker.cooldownMs = 1000; // 1s de cooldown pour accélérer le test unitaire
    });

    it('devrait démarrer à l\'état CLOSED et autoriser les résolutions', () => {
        expect(canAttemptDns()).toBe(true);
        expect(dnsCircuitBreaker.state).toBe('CLOSED');
    });

    it('devrait s\'ouvrir après avoir atteint le seuil d\'échecs (5)', () => {
        for (let i = 0; i < 4; i++) {
            recordDnsFailure();
            expect(canAttemptDns()).toBe(true);
            expect(dnsCircuitBreaker.state).toBe('CLOSED');
        }

        recordDnsFailure();
        expect(canAttemptDns()).toBe(false);
        expect(dnsCircuitBreaker.state).toBe('OPEN');
    });

    it('devrait passer en HALF-OPEN après expiration du cooldown', async () => {
        for (let i = 0; i < 5; i++) {
            recordDnsFailure();
        }
        expect(canAttemptDns()).toBe(false);

        await new Promise((resolve) => setTimeout(resolve, 1100));

        expect(canAttemptDns()).toBe(true);
        expect(dnsCircuitBreaker.state).toBe('HALF-OPEN');
    });

    it('devrait se refermer (CLOSED) après un succès en HALF-OPEN', async () => {
        for (let i = 0; i < 5; i++) {
            recordDnsFailure();
        }
        await new Promise((resolve) => setTimeout(resolve, 1100));
        expect(canAttemptDns()).toBe(true); // Passage en HALF-OPEN

        recordDnsSuccess();
        expect(dnsCircuitBreaker.state).toBe('CLOSED');
        expect(dnsCircuitBreaker.failureCount).toBe(0);
    });
});