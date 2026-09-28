/**
 * @vitest-environment jsdom
 */

import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import ClientLibrary from '../fingerprint.client.js';

describe('ClientLibrary WASM Integration', () => {
    beforeEach(() => {
        // Reset cache and spies before each test
        ClientLibrary._resetCache();
        vi.spyOn(console, 'log').mockImplementation(() => {});
        vi.spyOn(console, 'warn').mockImplementation(() => {});

        // Remove global mocks to prevent leakage across tests
        delete window.createFingerprintModule;
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should successfully load WASM module and switch hasher', async () => {
        // 1. Mock functional WASM module
        const mockWasmModule = {
            _hash_string: vi.fn((str) => 99999), // Distinct mock hash value
            _malloc: vi.fn().mockReturnValue(0),
            HEAPU8: new Uint8Array(4096)
        };

        // 2. Mock script loading and module factory
        window.createFingerprintModule = vi.fn().mockResolvedValue(mockWasmModule);

        // Mock script element injection with direct onload callback
        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            // Simulate successful script load
            script.onload();
            return script;
        });

        // 3. Initialize WASM module
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 4. Verify hasher was switched
        const wasmHash = ClientLibrary._hasher("test");
        expect(wasmHash).toBe(99999);
        expect(mockWasmModule._hash_string).toHaveBeenCalledWith(0);
        expect(console.log).toHaveBeenCalledWith(expect.stringContaining('WASM module loaded successfully'));
    });

    it('should gracefully fall back to JS hasher if WASM module fails to load', async () => {
        // 1. Simulate script loading failure
        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            script.onerror(new Error('Script loading failed'));
            return script;
        });

        // 2. Initialize WASM module
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 3. Verify hasher falls back to JS implementation
        const jsHash = ClientLibrary._hasher("test");
        const originalJsHash = (await import('../fingerprint.builder.js')).cyrb53("test");
        
        expect(jsHash).toBe(originalJsHash);
        expect(console.warn).toHaveBeenCalledWith(expect.stringContaining('WASM module failed to load'), expect.any(Error));
    });

    it('should gracefully fall back if WASM module does not export _hash_string', async () => {
        // 1. Simulate malformed WASM module missing required export
        const mockWasmModule = {};
        window.createFingerprintModule = vi.fn().mockResolvedValue(mockWasmModule);

        vi.spyOn(document.head, 'appendChild').mockImplementation((script) => {
            script.onload();
            return script;
        });

        // 2. Initialize WASM module
        await ClientLibrary.initializeWasm('/fake/path/to/fp.js');

        // 3. Verify fallback
        const jsHash = ClientLibrary._hasher("test");
        const originalJsHash = (await import('../fingerprint.builder.js')).cyrb53("test");
        expect(jsHash).toBe(originalJsHash); 
        // Verify both generic error log and specific missing export cause
        expect(console.warn).toHaveBeenCalledWith(
            expect.stringContaining('WASM module failed to load'), 
            expect.objectContaining({ message: 'WASM module did not export _hash_string.' })
        );
    });

    it('should successfully load raw WASM and use standalone polymorphic hasher', async () => {
        const mockWasmInstance = {
            exports: {
                memory: { buffer: new ArrayBuffer(65536) },
                hash: vi.fn().mockReturnValue(123456)
            }
        };
        
        global.WebAssembly = {
            compile: vi.fn().mockResolvedValue({}),
            instantiate: vi.fn().mockResolvedValue(mockWasmInstance)
        };
        
        global.fetch = vi.fn().mockResolvedValue({
            arrayBuffer: vi.fn().mockResolvedValue(new ArrayBuffer(100))
        });

        await ClientLibrary.initializeWasm('/fp.wasm');

        const hash = ClientLibrary._hasher("test");
        expect(hash).toBe(123456);
        expect(mockWasmInstance.exports.hash).toHaveBeenCalledWith(0, 4);
    });

    it('should use the default JS hasher if WASM is not configured', async () => {
        // Ensure no WASM path is provided in the config
        ClientLibrary.initializeClient({});

        // Verify that the active hasher is the original JS implementation
        const jsHash = ClientLibrary._hasher("another test string");
        const originalJsHash = (await import('../fingerprint.builder.js')).cyrb53("another test string");

        expect(jsHash).toBe(originalJsHash);
        // Ensure no WASM-related console logs or warnings were made
        expect(console.log).not.toHaveBeenCalledWith(expect.stringContaining('WASM module loaded successfully'));
        expect(console.warn).not.toHaveBeenCalledWith(expect.stringContaining('WASM module failed to load'));
    });
});