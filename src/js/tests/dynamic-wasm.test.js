import { describe, expect, it } from 'vitest';
import { DynamicWasmGenerator } from '../dynamic-wasm.js';

// Helper function to decode ULEB128 (for verification)
function decodeULEB128(bytes) {
    let result = 0;
    let shift = 0;
    for (const byte of bytes) {
        result |= (byte & 0x7f) << shift;
        if (!(byte & 0x80)) {
            break;
        }
        shift += 7;
    }
    return result;
}

describe('DynamicWasmGenerator', () => {
    it('should generate a valid WASM module buffer', () => {
        const constants = { seed: 123, multiplier: 33, adder: 7 };
        const wasmBuffer = DynamicWasmGenerator.generate(constants);

        // Basic check: ensure it's a Buffer and starts with WASM magic number
        expect(wasmBuffer).toBeInstanceOf(Buffer);
        expect(wasmBuffer.slice(0, 4).toString('hex')).toBe('0061736d'); // \0asm
        expect(wasmBuffer.slice(4, 8).toString('hex')).toBe('01000000'); // Version 1

        // Attempt to compile and instantiate the module to ensure validity
        let instance;
        try {
            const module = new WebAssembly.Module(wasmBuffer);
            instance = new WebAssembly.Instance(module, {});
        } catch (e) {
            // If compilation/instantiation fails, it's an invalid WASM module
            expect.fail(`Generated WASM module is invalid: ${e.message}`);
        }

        // Verify the exported hash function exists
        expect(instance.exports.hash).toBeInstanceOf(Function);
        expect(instance.exports.memory).toBeInstanceOf(WebAssembly.Memory);
    });

    it('should produce a consistent hash result with the JS fallback', () => {
        const constants = { seed: 42, multiplier: 1597334677, adder: 12345 };
        const testString = "hello world";

        const wasmBuffer = DynamicWasmGenerator.generate(constants);
        const module = new WebAssembly.Module(wasmBuffer);
        const instance = new WebAssembly.Instance(module, {});
        const exports = instance.exports;
        const memory = exports.memory;

        // Write string to WASM memory
        const encoder = new TextEncoder();
        const bytes = encoder.encode(testString);
        const view = new Uint8Array(memory.buffer);
        view.set(bytes, 0); // Assuming hash function expects string at address 0

        // Calculate hash using WASM
        const wasmHash = exports.hash(0, bytes.length);

        // Calculate hash using JS fallback
        const jsHash = DynamicWasmGenerator.hashJs(testString, constants);

        // The WASM and JS implementations should yield the same result
        expect(wasmHash).toBe(jsHash);
    });

    it('should generate different WASM modules for different constants', () => {
        const constants1 = { seed: 1, multiplier: 2, adder: 3 };
        const constants2 = { seed: 4, multiplier: 5, adder: 6 };

        const wasmBuffer1 = DynamicWasmGenerator.generate(constants1);
        const wasmBuffer2 = DynamicWasmGenerator.generate(constants2);

        expect(wasmBuffer1.toString('hex')).not.toBe(wasmBuffer2.toString('hex'));
    });
});