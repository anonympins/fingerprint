/**
 * @vitest-environment jsdom
 */

import { describe, expect, it, vi } from 'vitest';
import { GpuPowSolver } from '../gpu_pow.solver.js';

describe('GpuPowSolver - Chaotic Logistic Map PoW', () => {
    const seed = 'chaotic-pow-seed-test';
    const iterations = 1000;

    it('should hash seed deterministically to a float between 0 and 1', () => {
        const f1 = GpuPowSolver._hashSeedToFloat(seed);
        const f2 = GpuPowSolver._hashSeedToFloat(seed);
        const f3 = GpuPowSolver._hashSeedToFloat('another-seed');

        expect(f1).toBe(f2);
        expect(f1).toBeGreaterThanOrEqual(0);
        expect(f1).toBeLessThan(1);
        expect(f1).not.toBe(f3);
    });

    it('should verify a mathematically correct trajectory solution', () => {
        const numericSeed = GpuPowSolver._hashSeedToFloat(seed);
        const r = 3.9999;
        const rFloat = Math.fround(r);
        const solutions = [];

        for (let idx = 0; idx < 64; idx++) {
            let x = Math.fround(numericSeed + idx * 0.015);
            for (let i = 0; i < iterations; i++) {
                x = Math.fround(rFloat * x * Math.fround(1.0 - x));
            }
            solutions.push(x.toFixed(6));
        }

        const validSolution = solutions.join(',');

        // Verify the correct solution
        expect(GpuPowSolver.verify(seed, iterations, validSolution)).toBe(true);
    });

    it('should reject invalid solutions', () => {
        expect(GpuPowSolver.verify(seed, iterations, '')).toBe(false);
        expect(GpuPowSolver.verify(seed, iterations, null)).toBe(false);
        expect(GpuPowSolver.verify(seed, iterations, '1.0,2.0')).toBe(false); // Wrong length (should be 64)
    });

    it('should reject tampered solutions exceeding the threshold', () => {
        const numericSeed = GpuPowSolver._hashSeedToFloat(seed);
        const r = 3.9999;
        const rFloat = Math.fround(r);
        const solutions = [];

        for (let idx = 0; idx < 64; idx++) {
            let x = Math.fround(numericSeed + idx * 0.015);
            for (let i = 0; i < iterations; i++) {
                x = Math.fround(rFloat * x * Math.fround(1.0 - x));
            }
            solutions.push(x.toFixed(6));
        }

        // Tamper with the 12th channel (one of the default sample indices [0, 12, 35, 57])
        const tamperedSolutions = [...solutions];
        const originalVal = parseFloat(tamperedSolutions[12]);
        tamperedSolutions[12] = (originalVal + 0.0002).toFixed(6); // exceeding 1e-4 tolerance

        expect(GpuPowSolver.verify(seed, iterations, tamperedSolutions.join(','))).toBe(false);
    });

    it('should fallback to WebGL2 if WebGPU is not supported', async () => {
        // Mock WebGPU as undefined
        const originalGpu = global.navigator.gpu;
        Object.defineProperty(global.navigator, 'gpu', {
            value: undefined,
            writable: true,
            configurable: true
        });

        // Mock WebGL2 context
        const mockGl = {
            useProgram: vi.fn(),
            createBuffer: vi.fn(),
            bindBuffer: vi.fn(),
            bufferData: vi.fn(),
            enableVertexAttribArray: vi.fn(),
            vertexAttribPointer: vi.fn(),
            uniform1f: vi.fn(),
            uniform1i: vi.fn(),
            getUniformLocation: vi.fn(),
            getAttribLocation: vi.fn(),
            drawArrays: vi.fn(),
            readPixels: vi.fn((x, y, w, h, format, type, pixels) => {
                // Populate mock pixels with arbitrary valid floats
                for (let i = 0; i < pixels.length; i++) {
                    pixels[i] = 0.5;
                }
            })
        };

        const mockCanvas = {
            getContext: vi.fn().mockReturnValue(mockGl)
        };

        vi.spyOn(document, 'createElement').mockImplementation((tagName) => {
            if (tagName === 'canvas') return mockCanvas;
            return {};
        });

        vi.spyOn(GpuPowSolver, '_createProgram').mockReturnValue({});

        const result = await GpuPowSolver.solve(seed, 100);

        expect(result.platform).toBe('webgl2');
        expect(result.solution.split(',').length).toBe(64);
        vi.restoreAllMocks();
    });
});