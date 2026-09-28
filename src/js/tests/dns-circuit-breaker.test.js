import { describe, expect, it, beforeEach } from 'vitest';
import { __internal } from '../fingerprint.js';

const { dnsCircuitBreaker, recordDnsSuccess, recordDnsFailure, canAttemptDns } = __internal;

describe('DNS Circuit Breaker', () => {
    beforeEach(() => {
        dnsCircuitBreaker.state = 'CLOSED';
        dnsCircuitBreaker.failureCount = 0;
        dnsCircuitBreaker.lastStateChange = 0;
        dnsCircuitBreaker.threshold = 5;
        dnsCircuitBreaker.cooldownMs = 1000; // 1s cooldown to speed up test execution
    });

    it('should start in CLOSED state and allow lookups', () => {
        expect(canAttemptDns()).toBe(true);
        expect(dnsCircuitBreaker.state).toBe('CLOSED');
    });

    it('should transition to OPEN after reaching failure threshold (5)', () => {
        for (let i = 0; i < 4; i++) {
            recordDnsFailure();
            expect(canAttemptDns()).toBe(true);
            expect(dnsCircuitBreaker.state).toBe('CLOSED');
        }

        recordDnsFailure();
        expect(canAttemptDns()).toBe(false);
        expect(dnsCircuitBreaker.state).toBe('OPEN');
    });

    it('should transition to HALF-OPEN after cooldown expires', async () => {
        for (let i = 0; i < 5; i++) {
            recordDnsFailure();
        }
        expect(canAttemptDns()).toBe(false);

        await new Promise((resolve) => setTimeout(resolve, 1100));

        expect(canAttemptDns()).toBe(true);
        expect(dnsCircuitBreaker.state).toBe('HALF-OPEN');
    });

    it('should reset to CLOSED after a success while in HALF-OPEN', async () => {
        for (let i = 0; i < 5; i++) {
            recordDnsFailure();
        }
        await new Promise((resolve) => setTimeout(resolve, 1100));
        expect(canAttemptDns()).toBe(true); // Transition to HALF-OPEN

        recordDnsSuccess();
        expect(dnsCircuitBreaker.state).toBe('CLOSED');
        expect(dnsCircuitBreaker.failureCount).toBe(0);
    });
});