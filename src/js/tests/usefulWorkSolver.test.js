import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { solveChallenge } from '../pow.solver.js'; // Assuming pow.solver.js is the ES module version

// Mock crypto.subtle for hashing operations
const mockSubtleDigest = vi.fn(async (algorithm, data) => {
    // Return a consistent mock hash for testing purposes
    const hash = new Uint8Array(32); // 32 bytes for SHA-256
    for (let i = 0; i < hash.length; i++) {
        hash[i] = i; // Simple predictable hash
    }
    return hash.buffer;
});

// Mock Math.random for deterministic optimization results
const mockMathRandom = vi.fn(() => 0.5);

// Mock IndexedDB for pospace challenges, even if not directly used by this test
const mockIndexedDB = {
    open: vi.fn(() => ({
        onupgradeneeded: null,
        onsuccess: null,
        onerror: null,
        result: {
            objectStoreNames: { contains: vi.fn(() => true) },
            createObjectStore: vi.fn(),
            transaction: vi.fn(() => ({
                objectStore: vi.fn(() => ({
                    put: vi.fn(),
                    get: vi.fn(() => ({ onsuccess: null, result: null }))
                }))
            }))
        }
    }))
};

describe('Useful Work Solver for Optimization Challenges', () => {
    let originalMathRandom;
    let originalIndexedDB;

    beforeEach(() => {
        // Save original implementations
        originalMathRandom = global.Math.random;
        originalIndexedDB = global.indexedDB;

        // Mock global objects
        vi.stubGlobal('crypto', {
            subtle: {
                digest: mockSubtleDigest,
            },
            randomInt: vi.fn((min, max) => Math.floor(mockMathRandom() * (max - min) + min)), // Mock randomInt for crypto
            randomBytes: vi.fn((length) => new Uint8Array(length).fill(0x01)), // Mock randomBytes for crypto
        });
        global.Math.random = mockMathRandom;
        global.indexedDB = mockIndexedDB;

        // Reset mocks
        mockSubtleDigest.mockClear();
        mockMathRandom.mockClear();
        mockIndexedDB.open.mockClear();
    });

    afterEach(() => {
        // Restore original implementations
        vi.unstubAllGlobals();
        global.Math.random = originalMathRandom;
        global.indexedDB = originalIndexedDB;
    });

    it('should solve a "useful_work_task" with fraud.solve and return a Pareto front', async () => {
        const mockChallenge = {
            type: 'useful_work_task',
            nonce: 'test-nonce-fraud',
            usefulWorkTask: {
                problemId: 'fraud_detection_challenge',
                task: {
                    type: 'multi_objective_genetic_algorithm',
                    solverName: 'fraud.solve',
                    generations: 5, // Keep generations low for quick test
                    populationSize: 10, // Keep population low for quick test
                    payload: {
                        legitimateClicks: [
                            { fingerprint: 'fp1', timeToClick: 500, clickX: 10, clickY: 10, mouseEntropy: 0.8, scrollEvents: 5 },
                            { fingerprint: 'fp1', timeToClick: 600, clickX: 12, clickY: 12, mouseEntropy: 0.7, scrollEvents: 6 },
                            { fingerprint: 'fp2', timeToClick: 700, clickX: 20, clickY: 20, mouseEntropy: 0.9, scrollEvents: 7 },
                        ],
                        fraudulentClicks: [
                            { fingerprint: 'fp3', timeToClick: 50, clickX: 5, clickY: 5, mouseEntropy: 0.1, scrollEvents: 0 },
                            { fingerprint: 'fp3', timeToClick: 60, clickX: 6, clickY: 6, mouseEntropy: 0.2, scrollEvents: 1 },
                            { fingerprint: 'fp4', timeToClick: 100, clickX: 10, clickY: 10, mouseEntropy: 0.3, scrollEvents: 2 },
                        ],
                    },
                },
            },
        };

        const solution = await solveChallenge(mockChallenge);

        // Assert the structure of the returned solution
        expect(solution.type).toBe('useful_work_task');
        expect(solution.nonce).toBe('test-nonce-fraud');
        expect(solution.rawSolution).toHaveProperty('problem_id', 'fraud_detection_challenge');
        expect(solution.rawSolution).toHaveProperty('work_result');

        const workResult = solution.rawSolution.work_result;
        expect(workResult).toHaveProperty('paretoFront');
        expect(workResult.paretoFront).toBeInstanceOf(Array);
        expect(workResult.paretoFront.length).toBeGreaterThan(0);

        // Check the structure of a single solution in the Pareto front
        const firstParetoSolution = workResult.paretoFront[0];
        expect(firstParetoSolution).toHaveProperty('solution');
        expect(firstParetoSolution.solution).toBeInstanceOf(Array); // fraud.solve returns an array of thresholds
        expect(firstParetoSolution.solution.length).toBe(4); // [minTimeToClick, maxClickVariance, minMouseEntropy, minScrollEvents]
        expect(firstParetoSolution).toHaveProperty('objectives');
        expect(firstParetoSolution.objectives).toBeInstanceOf(Array); // [objective1, objective2]
        expect(firstParetoSolution.objectives.length).toBe(2);
    }, 10000); // Increase timeout for GA, even with low generations/population

    it('should solve a "useful_work_task" with cpc.solve and return a Pareto front', async () => {
        const mockChallenge = {
            type: 'useful_work_task',
            nonce: 'test-nonce-cpc',
            usefulWorkTask: {
                problemId: 'cpc_optimization_challenge',
                task: {
                    type: 'multi_objective_genetic_algorithm',
                    solverName: 'cpc.solve',
                    generations: 5, // Keep generations low for quick test
                    populationSize: 10, // Keep population low for quick test
                    payload: {
                        platformParams: { optimalBaseCommission: 0.3, optimalBonusFactor: 0.1 },
                        website: { relevanceScore: 70 },
                        advertiser: { credits: 1000 },
                        estimatedImpressions: 500,
                        competingAds: [{ id: 'ad1' }, { id: 'ad2' }],
                    },
                },
            },
        };

        const solution = await solveChallenge(mockChallenge);

        // Assert the structure of the returned solution
        expect(solution.type).toBe('useful_work_task');
        expect(solution.nonce).toBe('test-nonce-cpc');
        expect(solution.rawSolution).toHaveProperty('problem_id', 'cpc_optimization_challenge');
        expect(solution.rawSolution).toHaveProperty('work_result');

        const workResult = solution.rawSolution.work_result;
        expect(workResult).toHaveProperty('paretoFront');
        expect(workResult.paretoFront).toBeInstanceOf(Array);
        expect(workResult.paretoFront.length).toBeGreaterThan(0);

        // Check the structure of a single solution in the Pareto front
        const firstParetoSolution = workResult.paretoFront[0];
        expect(firstParetoSolution).toHaveProperty('solution');
        expect(typeof firstParetoSolution.solution).toBe('number'); // cpc.solve returns a single CPC value
        expect(firstParetoSolution).toHaveProperty('objectives');
        expect(firstParetoSolution.objectives).toBeInstanceOf(Array); // [platformRevenue, advertiserValue, marketImbalance]
        expect(firstParetoSolution.objectives.length).toBe(3);
    }, 10000);
});