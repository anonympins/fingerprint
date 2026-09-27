import {describe, expect, it} from 'vitest';
import {FingerprintBuilder} from '../fingerprint.builder.js';

describe('FingerprintBuilder.compare', () => {

    // Realistic fingerprint for a legitimate user (e.g. Chrome on Windows)
    // Recorded during baseline initial visit.
    const realisticOriginalFp = new FingerprintBuilder()
        .add('cvs', 'mock-canvas-data-v1')
        .add('gpu', 'ANGLE (NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)')
        .add('hw', '16_8_0') // 16 cores, 8GB RAM, no touch
        .add('os', 'Win32')
        .add('ua', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36')
        .add('ja3', '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0')
        // Volatile headers that may legitimately change during challenge solving
        .add('cookie_keys', '_ga,session,device_id')
        .add('upgrade', '1')
        .toString();

    it('should return a similarity score of 1.0 for the same device with minor volatile changes', () => {
        // Success scenario: user solves a challenge.
        // Solver fingerprint is identical except for volatile headers
        // (such as cookie presence or upgrade-insecure-requests) which compare ignores.
        const realisticSolverFp = new FingerprintBuilder()
            .add('cvs', 'mock-canvas-data-v1') // Identique
            .add('gpu', 'ANGLE (NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0)') // Identique
            .add('hw', '16_8_0') // Identique
            .add('os', 'Win32') // Identique
            .add('ua', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36') // Identique
            .add('ja3', '771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0') // Identique
            // 'cookie_keys' is omitted, simulating a request without cookies
            // 'upgrade' header is also omitted
            .toString();

        const similarity = FingerprintBuilder.compare(realisticOriginalFp, realisticSolverFp);

        // Similarity remains 1.0 because all differences reside in ignored volatile keys
        expect(similarity).toBe(1.0);
    });

    it('should return a low similarity score for two completely different devices', () => {
        // Failure scenario: attacker steals device_id cookie and attempts
        // challenge resolution from a different machine (e.g. Linux VM with Firefox).
        const differentSolverFp = new FingerprintBuilder()
            .add('cvs', 'different-canvas-data') // Différent
            .add('gpu', 'llvmpipe (LLVM 15.0.7, 256 bits)') // Différent (GPU de VM)
            .add('hw', '8_4_0') // Différent
            .add('os', 'Linux x86_64') // Différent
            .add('ua', 'Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0') // Différent
            .add('ja3', '771,49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,65281-11-10-35-16-5-13-51-45-43-27-23-17513,29-23-24,0') // Différent (JA3 de Firefox)
            .toString();

        const similarity = FingerprintBuilder.compare(realisticOriginalFp, differentSolverFp);

        // Similarity should be very low (close to 0) since invariant signals differ
        expect(similarity).toBeLessThan(0.1);
    });

    it('should return 0 if one of the fingerprints is null or empty', () => {
        expect(FingerprintBuilder.compare(realisticOriginalFp, null)).toBe(0);
        expect(FingerprintBuilder.compare(null, realisticOriginalFp)).toBe(0);
        expect(FingerprintBuilder.compare(realisticOriginalFp, '')).toBe(0);
        expect(FingerprintBuilder.compare('', realisticOriginalFp)).toBe(0);
        expect(FingerprintBuilder.compare(null, null)).toBe(0);
    });

    it('should handle fingerprints with missing components gracefully', () => {
        const partialFp = new FingerprintBuilder()
            .add('ua', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36')
            .add('os', 'Win32')
            .toString(); // Missing GPU, canvas, etc.

        const similarity = FingerprintBuilder.compare(realisticOriginalFp, partialFp);
        expect(similarity).toBeGreaterThan(0);
        expect(similarity).toBeLessThan(1);
    });
});