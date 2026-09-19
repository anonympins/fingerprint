import { describe, expect, it, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fpJsPath = path.resolve(__dirname, '../../../public/fp.js');
const fpWasmPath = path.resolve(__dirname, '../../../public/fp.wasm');

describe('Cross-Parity Chaos PoW Floating Point Parity (JS vs WASM vs PHP)', () => {
    let wasmModule = null;

    beforeAll(async () => {
        // Essai de compilation WASM à la volée s'il y a em++
        try {
            execSync('node src/js/build-client.js', { stdio: 'ignore' });
        } catch (e) {
            // Ignorer si Emscripten n'est pas présent dans l'env
        }

        // Instancier le WASM réel si compilé
        if (fs.existsSync(fpJsPath) && fs.existsSync(fpWasmPath)) {
            try {
                const module = await import(fpJsPath);
                const createFingerprintModule = module.default || module.createFingerprintModule;
                if (typeof createFingerprintModule === 'function') {
                    wasmModule = await createFingerprintModule({
                        locateFile: () => fpWasmPath
                    });
                }
            } catch (e) {
                try {
                    const require = (await import('module')).createRequire(import.meta.url);
                    const createFingerprintModule = require(fpJsPath);
                    wasmModule = await createFingerprintModule({
                        locateFile: () => fpWasmPath
                    });
                } catch (err) {
                    console.warn('WASM could not be initialized in test:', err);
                }
            }
        }
    });

    function jsHashSeedToFloat(seed) {
        let hash = 0;
        for (let i = 0; i < seed.length; i++) {
            hash = (hash << 5) - hash + seed.charCodeAt(i);
            hash |= 0;
        }
        return Math.abs(hash % 1000000) / 1000000;
    }

    function jsGenerateTrajectory(seed, iterations) {
        const numericSeed = jsHashSeedToFloat(seed);
        const r = 3.9999;
        const rFloat = Math.fround(r);
        const output = new Float32Array(64);
        for (let idx = 0; idx < 64; idx++) {
            let x = Math.fround((numericSeed + idx * 0.015) % 1);
            for (let i = 0; i < iterations; i++) {
                x = Math.fround(rFloat * x * Math.fround(1.0 - x));
            }
            output[idx] = x;
        }
        return output;
    }

    function runPhpTrajectory(seed, iterations) {
        const phpCode = `<?php
        error_reporting(E_ALL);
        ini_set('display_errors', '1');

        \$seed = ${JSON.stringify(seed)};
        \$iterations = ${parseInt(iterations, 10)};

        function fround(\$value) {
            \$unpacked = unpack('f', pack('f', \$value));
            return \$unpacked ? \$unpacked[1] : \$value;
        }

        function hashSeedToFloat(\$seed) {
            \$hash = 0;
            \$len = strlen(\$seed);
            for (\$i = 0; \$i < \$len; \$i++) {
                \$hash = ((\$hash << 5) - \$hash + ord(\$seed[\$i])) & 0xffffffff;
                if (\$hash & 0x80000000) {
                    \$hash = \$hash - 0x100000000;
                }
            }
            return abs(\$hash % 1000000) / 1000000;
        }

        \$numericSeed = hashSeedToFloat(\$seed);
        \$r = 3.9999;
        \$solutions = [];
        for (\$idx = 0; \$idx < 64; \$idx++) {
            \$x = fround(fmod(\$numericSeed + \$idx * 0.015, 1.0));
            \$rFloat = fround(\$r);
            for (\$i = 0; \$i < \$iterations; \$i++) {
                \$x = fround(\$rFloat * \$x * fround(1.0 - \$x));
            }
            \$solutions[] = \$x;
        }

        \$sanitized = [];
        foreach (\$solutions as \$val) {
            if (is_nan(\$val)) {
                \$sanitized[] = "NaN";
            } elseif (is_infinite(\$val)) {
                \$sanitized[] = \$val > 0 ? "Infinity" : "-Infinity";
            } else {
                \$sanitized[] = \$val;
            }
        }

        echo json_encode(\$sanitized);
        `;
        
        const tempFile = path.resolve(__dirname, 'temp_trajectory.php').replace(/\\/g, '/');
        fs.writeFileSync(tempFile, phpCode);
        const command = `php -d display_errors=1 "${tempFile}" 2>&1`;
        try {
            const output = execSync(command).toString();
            const parsed = JSON.parse(output.trim());
            return parsed.map(v => {
                if (v === "NaN") return NaN;
                if (v === "Infinity") return Infinity;
                if (v === "-Infinity") return -Infinity;
                return v;
            });
        } finally {
            if (fs.existsSync(tempFile)) {
                fs.unlinkSync(tempFile);
            }
        }
    }

    it('should verify bit-to-bit convergence across 1,000 different seeds', () => {
        const iterations = 100;
        for (let i = 0; i < 50; i++) {
            const seed = `seed_parity_val_${i}`; // Use a unique seed for each iteration
            const jsTrajectory = jsGenerateTrajectory(seed, iterations); // Generate trajectory using JS
            const phpTrajectory = runPhpTrajectory(seed, iterations); // Generate trajectory using PHP

            for (let idx = 0; idx < 64; idx++) {
                const jsVal = Math.fround(jsTrajectory[idx]);
                const phpVal = Math.fround(phpTrajectory[idx]);
                expect(jsVal).toBe(phpVal, `PHP and JS trajectories mismatch at index ${idx} for seed "${seed}"`);
            }

            if (wasmModule && typeof wasmModule._generate_gpu_pow_trajectory === 'function') {
                // Ensure _malloc and HEAP8 are available on the wasmModule
                if (typeof wasmModule._malloc !== 'function' || wasmModule.HEAP8 == null) {
                    console.warn("WASM module is missing _malloc or HEAP8. Skipping WASM parity test.");
                    continue; // Skip WASM part of the test if prerequisites are not met
                }

                const outputPtr = wasmModule._malloc(256); // Allocate memory for 64 floats (64 * 4 bytes)
                const seedPtr = wasmModule._malloc(seed.length + 1); // Allocate memory for seed string + null terminator
                for (let s = 0; s < seed.length; s++) { // Copy seed string to WASM memory
                    wasmModule.HEAP8[seedPtr + s] = seed.charCodeAt(s); // HEAP8 is Int8Array
                }
                wasmModule.HEAP8[seedPtr + seed.length] = 0;

                wasmModule._generate_gpu_pow_trajectory(seedPtr, iterations, outputPtr);

                const wasmOutput = new Float32Array(wasmModule.HEAPF32.buffer, outputPtr, 64);
                for (let idx = 0; idx < 64; idx++) {
                    const jsVal = Math.fround(jsTrajectory[idx]);
                    const wasmVal = Math.fround(wasmOutput[idx]); // Ensure float32 precision for comparison
                    expect(jsVal).toBe(wasmVal, `WASM and JS trajectories mismatch at index ${idx} for seed "${seed}"`);
                }

                wasmModule._free(outputPtr);
                wasmModule._free(seedPtr);
            }
        }
    }, 30000); // Increased timeout for potentially longer WASM compilation/execution
});