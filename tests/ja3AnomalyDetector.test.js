import crypto from 'crypto';
import {getTlsSpoofingScore, parseJa3} from '../src/js/fingerprint.js';
import {vi} from 'vitest';

describe('JA3 Anomaly Detector (Node.js)', () => {
    
    // Mock d'un store de cache asynchrone en mémoire
    const createMockStore = () => {
        const storage = {};
        return {
            get: vi.fn(async (key) => storage[key] || null),
            set: vi.fn(async (key, val) => { storage[key] = val; })
        };
    };

    describe('parseJa3', () => {
        it('devrait parser correctement une chaine JA3 brute', () => {
            const rawJa3 = '771,4865-4866-4867,0-23-65281-10-11,29-23-24,0';
            const parsed = parseJa3(rawJa3);
            
            expect(parsed).not.toBeNull();
            expect(parsed.tlsVersion).toBe(771);
            expect(parsed.ciphers).toEqual([4865, 4866, 4867]);
            expect(parsed.extensions).toEqual([0, 23, 65281, 10, 11]);
        });

        it('devrait retourner null pour des chaines invalides', () => {
            expect(parseJa3('')).toBeNull();
            expect(parseJa3('771,4865')).toBeNull();
        });
    });

    describe('getTlsSpoofingScore (Anomalies JA3 hachées)', () => {
        it('devrait détecter l\'usurpation d\'identité d\'une bibliothèque (Python)', async () => {
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

        it('devrait détecter la rotation d\'User-Agent sur un même hash JA3 (Stagnation)', async () => {
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

            // Injecter le mockStore dans le module de test si nécessaire ou mocker l'importation du store global
            // Premier passage : Chrome
            const res1 = await getTlsSpoofingScore(contextChrome, mockStore);
            
            // Deuxième passage : Firefox (Détection de la rotation de UA)
            const res2 = await getTlsSpoofingScore(contextFirefox, mockStore);
            expect(res2.tlsSpoofingScore).toBe(85);
        });
    });

    describe('getTlsSpoofingScore (Anomalies JA3 brutes)', () => {
        it('devrait suspecter un faux Chrome n\'utilisant pas le mécanisme GREASE', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // Pas de valeurs GREASE dans la suite
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

        it('devrait valider un Chrome légitime utilisant des valeurs GREASE', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // 2570 est une suite GREASE valide
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

        it('devrait détecter l\'absence d\'extension ALPN pour une connexion HTTP/2', async () => {
            const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0';
            // Pas d'extension 16 (ALPN)
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
