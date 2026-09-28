import crypto from 'crypto';
import {getTlsSpoofingScore, parseJa3} from '../fingerprint.js';
import {vi} from 'vitest';
import { verifyZkpProof, decodePolymorphicFingerprint, deepMerge, getHeaderSignature, parseJa3, modPow, hashNetwork, normalizeReferer, isPrivateIp, parseUserAgent } from "../../js/fingerprint.utils.js";

describe('JA3 Anomaly Detector (Node.js)', () => {
    
    // Mock async in-memory cache store
    const createMockStore = () => {
        const storage = {};
        return {
            get: vi.fn(async (key) => storage[key] || null),
            set: vi.fn(async (key, val) => { storage[key] = val; })
        };
    };

    describe('parseJa3', () => {
        it('should correctly parse raw JA3 string', () => {
            const rawJa3 = '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0';
            const parsed = parseJa3(rawJa3);
            
            expect(parsed).not.toBeNull();
            expect(parsed.tlsVersion).toBe(771);
            expect(parsed.ciphers).toEqual([4865, 4866, 4867]);
            expect(parsed.extensions).toEqual([0, 23, 65281, 10, 11]);
        });

        it('should return null for invalid strings', () => {
            expect(parseJa3('')).toBeNull();
            expect(parseJa3('771,4865')).toBeNull();
        });
    });

    describe('getTlsSpoofingScore (Anomalies JA3 hachées)', () => {
        it('should detect library spoofing (Python)', async () => {
            const pythonJa3Hash = '47344a349b75c4e82333475553b5f358';
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';

            const context = {
                headers: {
                    'user-agent': chromeUa,
                    'x-ja3-hash': pythonJa3Hash
                }
            };

            const result = await getTlsSpoofingScore(context);
            expect(result.tlsSpoofingScore).toBe(90);
        });

        it('should detect User-Agent rotation on identical JA3 hash (Stagnation)', async () => {
            const mockStore = createMockStore();
            const unknownJa3 = '00000000000000000000000000000000';
            
            const contextChrome = {
                headers: {
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
                    'x-ja3-hash': unknownJa3
                }
            };

            const contextFirefox = {
                headers: {
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/120.0',
                    'x-ja3-hash': unknownJa3
                }
            };

            // First call: Chrome
            const res1 = await getTlsSpoofingScore(contextChrome, mockStore);
            
            // Second call: Firefox (Detects UA rotation)
            const res2 = await getTlsSpoofingScore(contextFirefox, mockStore);
            expect(res2.tlsSpoofingScore).toBe(85);
        });
    });

    describe('getTlsSpoofingScore (Anomalies JA3 brutes)', () => {
        it('should flag fake Chrome lacking GREASE values', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // No GREASE values in ciphers/extensions
            const ja3RawNoGrease = '771,4865-4866,0-23-10,29,0';
            const ja3Hash = crypto.createHash('md5').update(ja3RawNoGrease).digest('hex');

            const context = {
                headers: {
                    'user-agent': chromeUa,
                    'x-ja3-raw': ja3RawNoGrease,
                    'x-ja3-hash': ja3Hash
                },
                httpVersion: '2.0'
            };

            const result = await getTlsSpoofingScore(context);
            expect(result.tlsSpoofingScore).toBe(75);
        });

        it('should validate legitimate Chrome using GREASE values', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // 2570 is a valid GREASE value
            const ja3RawWithGrease = '771,4865-2570,0-23-10-16,29,0';
            const ja3Hash = crypto.createHash('md5').update(ja3RawWithGrease).digest('hex');

            const context = {
                headers: {
                    'user-agent': chromeUa,
                    'x-ja3-raw': ja3RawWithGrease,
                    'x-ja3-hash': ja3Hash
                },
                httpVersion: '2.0'
            };

            const result = await getTlsSpoofingScore(context);
            expect(result.tlsSpoofingScore).toBeLessThan(70);
        });

        it('should detect missing ALPN extension on HTTP/2 connections', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // Missing extension 16 (ALPN)
            const ja3RawNoAlpn = '771,4865-2570,0-23-10,29,0';
            const ja3Hash = crypto.createHash('md5').update(ja3RawNoAlpn).digest('hex');

            const context = {
                headers: {
                    'user-agent': chromeUa,
                    'x-ja3-raw': ja3RawNoAlpn,
                    'x-ja3-hash': ja3Hash
                },
                httpVersion: '2.0'
            };

            const result = await getTlsSpoofingScore(context);
            expect(result.tlsSpoofingScore).toBe(70);
        });
    });
});
