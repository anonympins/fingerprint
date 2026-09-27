import { describe, expect, it } from 'vitest';
import { __internal } from '../fingerprint.js';

describe('Polymorphic System and Obfuscation Compiler', () => {
    
    it('should generate a valid session mapping with randomized headers and globals', () => {
        const mapping1 = __internal.generateSessionMapping();
        const mapping2 = __internal.generateSessionMapping();

        // Verify expected mapping structure
        expect(mapping1).toBeDefined();
        expect(mapping1.headers).toHaveProperty('x-device-fingerprint');
        expect(mapping1.headers).toHaveProperty('x-behavior-metrics');
        expect(mapping1.globals).toHaveProperty('ClientLibrary');
        expect(mapping1.globals).toHaveProperty('getDeviceFingerprint');
        expect(mapping1.globals).toHaveProperty('getClientBehaviorMetrics');
        expect(mapping1.keys).toHaveProperty('ua');
        expect(mapping1.wasmConstants).toHaveProperty('seed');

        // Verify randomness: two consecutive sessions must yield unique mappings
        expect(mapping1.headers['x-device-fingerprint']).not.toBe(mapping2.headers['x-device-fingerprint']);
        expect(mapping1.globals['ClientLibrary']).not.toBe(mapping2.globals['ClientLibrary']);
        expect(mapping1.keys['ua']).not.toBe(mapping2.keys['ua']);
        expect(mapping1.wasmConstants.seed).not.toBe(mapping2.wasmConstants.seed);
    });

    it('should compile and obfuscate client script asynchronously using the obfuscation worker', async () => {
        const mapping = __internal.generateSessionMapping();
        
        // Run background worker obfuscation task
        const obfuscatedCode = await __internal.compilePolymorphicJs(mapping);

        expect(obfuscatedCode).toBeDefined();
        expect(typeof obfuscatedCode).toBe('string');
        expect(obfuscatedCode.length).toBeGreaterThan(0);

        // Verify original identifiers were rewritten in compiled client script
        expect(obfuscatedCode).not.toContain('X-Device-Fingerprint');
        expect(obfuscatedCode).not.toContain('X-Behavior-Metrics');
        expect(obfuscatedCode).not.toContain('ClientLibrary');

        // Verify code is obfuscated without plain dev comments
        expect(obfuscatedCode).not.toContain('// Nom trompeur aléatoire pour attirer les analyseurs');
        
        // Obfuscator emits string array wrapper prefix
        expect(obfuscatedCode).toMatch(/_0x/);
    }, 15000); // 15s timeout for CPU-intensive worker execution
});