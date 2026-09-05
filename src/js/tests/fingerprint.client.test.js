/**
 * @vitest-environment jsdom
 */

import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import ClientLibrary from '../fingerprint.client.js';

describe('ClientLibrary WASM Integration', () => {
    beforeEach(() => {
        // Réinitialise le cache et les mocks avant chaque test
        ClientLibrary._resetCache();
        vi.spyOn(console, 'log').mockImplementation(() => {});
        vi.spyOn(console, 'warn').mockImplementation(() => {});

        // Supprime les mocks globaux pour éviter les fuites entre les tests
        delete window.createFingerprintModule;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should successfully load WASM module and switch hasher', async () => {
        // 1. Simuler un module WASM fonctionnel
        const mockWasmModule = {
            _hash_string: vi.fn((str) => 99999), // Un mock qui retourne une valeur distincte
        };

        // 2. Simuler le chargement du script et l'initialisation du module
        // On attache les fonctions de simulation à `window` car c'est ce que le code cherche
        window.createFingerprintModule = vi.fn().mockResolvedValue(mockWasmModule);

        // On simule l'injection du script en appelant directement `onload`
        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            // Simule le chargement réussi du script
            script.onload();
            return script;
        });

        // 3. Appeler la fonction d'initialisation
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 4. Vérifier que le hasher a été remplacé
        const wasmHash = ClientLibrary._hasher("test");
        expect(wasmHash).toBe(99999);
        expect(mockWasmModule._hash_string).toHaveBeenCalledWith("test");
        expect(console.log).toHaveBeenCalledWith(expect.stringContaining('WASM module loaded successfully'));
    });

    it('should gracefully fall back to JS hasher if WASM module fails to load', async () => {
        // 1. Simuler un échec de chargement du script
        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            script.onerror(new Error('Script loading failed'));
            return script;
        });

        // 2. Appeler la fonction d'initialisation
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 3. Vérifier que le hasher est toujours l'implémentation JS
        const jsHash = ClientLibrary._hasher("test");
        const originalJsHash = (await import('../fingerprint.builder.js')).cyrb53("test");
        
        expect(jsHash).toBe(originalJsHash);
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('WASM module failed to load'), expect.any(Error));
    });

    it('should gracefully fall back if WASM module does not export _hash_string', async () => {
        // 1. Simuler un module WASM malformé (sans la fonction attendue)
        const mockWasmModule = {};
        window.createFingerprintModule = vi.fn().mockResolvedValue(mockWasmModule);

        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            script.onload();
            return script;
        });

        // 2. Appeler la fonction d'initialisation
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 3. Vérifier le fallback
        const jsHash = ClientLibrary._hasher("test");
        const originalJsHash = (await import('../fingerprint.builder.js')).cyrb53("test");
        expect(jsHash).toBe(originalJsHash); 
        // L'assertion est maintenant plus précise : elle vérifie le message générique ET le message d'erreur spécifique.
        expect(console.warn).toHaveBeenCalledWith(
            expect.stringContaining('WASM module failed to load'), 
            expect.objectContaining({ message: 'WASM module did not export _hash_string.' })
        );
    });
});