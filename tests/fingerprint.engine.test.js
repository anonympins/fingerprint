import { it, describe, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fingerprint from '../fingerprint.js';
import { solveCpuTargetInline, solveMemory } from '../pow.solver.js';

// Mock the internal store to be a simple in-memory map for testing
const inMemoryStore = {
    _map: new Map(),
    async get(key) { return this._map.get(key); },
    async set(key, value, ttl) { this._map.set(key, value); },
    async has(key) { return this._map.has(key); },
    async delete(key) { this._map.delete(key); },
    clear() { this._map.clear(); }
};

vi.mock('../fingerprint.js', async (importOriginal) => {
    const original = await importOriginal();
    return {
        ...original,
        getCompositeDeviceHash: vi.fn().mockImplementation((context) => context.headers['x-device-fingerprint'] || 'default-fingerprint'),
        __internal: { ...original.__internal, getCompositeDeviceHash: vi.fn().mockImplementation((context) => context.headers['x-device-fingerprint'] || 'default-fingerprint') }
    };
});

describe('FingerprintEngine Challenge Validation', () => {
    let engine;
    const securityConfig = {
        weights: {
            historyScore: 0,
            rotationScore: 0,
            headerAnomalyScore: 0.2,
            inconsistencyScore: 0,
            honeypotScore: 1,
            requestPatternScore: 0,
            maliciousContentScore: 1
        },
        thresholds: { low: 15, medium: 40, high: 75, block: 95 },
        challengeTtl: 300,
        verbose: false,
    };

    beforeEach(() => {
        // Configure the engine to use our mock store before each test
        fingerprint.configureStore(inMemoryStore);
        inMemoryStore.clear();
        engine = new fingerprint.FingerprintEngine(securityConfig);
    });

    afterEach(() => {
        vi.restoreAllMocks();
    });

    it('should validate a correct challenge solution with a matching fingerprint', async () => {
        // --- 1. First request: A suspicious user gets a challenge ---
        const originalRequestContext = {
            clientIp: '127.0.0.1',
            path: '/sensitive-data',
            cookies: {},
            query: {},
            headers: {
                'user-agent': 'A-Legit-Browser/1.0',
                'x-device-fingerprint': 'fingerprint-A' // The fingerprint of the original machine
            },
            isStatic: false,
            rawReq: { headers: { accept: 'text/html' } }
        };

        // Force a high score to trigger a challenge
        vi.spyOn(engine, 'calculateFinalScore').mockReturnValueOnce(20);

        const challengeDecision = await engine.processRequest(originalRequestContext);

        expect(challengeDecision.action).toBe('challenge');
        expect(challengeDecision.status).toBe(404);

        // Extract challenge details from the HTML body (simplified parsing)
        const body = challengeDecision.body;
        const nonce = body.match(/const nonce = "(.*?)"/)[1];
        const cpuTarget = body.match(/const cpuTarget = BigInt\("0x" \+ "([0-9a-fA-F]+)"\)/)[1];
        const memDifficulty = parseInt(body.match(/const memDifficulty = (\d+)/)[1], 10);

        // Check that the challenge context was stored correctly
        const challengeContext = await inMemoryStore.get(`secret:${nonce}`);
        expect(challengeContext).toBeDefined();
        expect(challengeContext.fingerprint).toBe('fingerprint-A');

        // --- 2. Second request: The user submits the solved challenge ---

        // The client solves the challenge
        // --- FIX: Simulate the client creating the baseBlock for the solver ---
        const messageBase = `${nonce}:${challengeContext.clientSecret}:fingerprint-A:`;
        const baseBlock = new TextEncoder().encode(messageBase);

        const cpuSolution = await solveCpuTargetInline(baseBlock, cpuTarget, null);
        // The memory challenge seed does not include the fingerprint.
        const memSeed = `${nonce}:${challengeContext.clientSecret}`;
        const memSolution = await solveMemory(memSeed, memDifficulty);

        const submissionRequestContext = {
            clientIp: '127.0.0.1',
            path: '/sensitive-data',
            cookies: {},
            query: {
                pow_type: 'cpu_mem',
                pow_nonce: nonce,
                pow_solution_cpu: String(cpuSolution),
                pow_solution_mem: String(memSolution),
                pow_fp: 'fingerprint-A' // The client correctly submits its fingerprint
            },
            headers: {
                'user-agent': 'A-Legit-Browser/1.0',
                'x-device-fingerprint': 'fingerprint-A' // The headers still match
            },
            isStatic: false,
            rawReq: { headers: { accept: 'text/html' } }
        };

        const validationDecision = await engine.processRequest(submissionRequestContext);

        // Assert: The solution is valid, so we expect a redirect with a clearance cookie
        expect(validationDecision.action).toBe('redirect');
        expect(validationDecision.path).toBe('/sensitive-data');
        expect(validationDecision.cookie.name).toBe('pow_clearance');
        expect(validationDecision.cookie.value).toBeDefined();

        // Assert: The challenge secret is deleted from the store
        expect(await inMemoryStore.has(`secret:${nonce}`)).toBe(false);
    }, 20000);

    it('should reject a challenge solution with a mismatched fingerprint', async () => {
        // --- 1. First request: Challenge is issued to "Machine A" ---
        const originalRequestContext = {
            clientIp: '127.0.0.1',
            path: '/sensitive-data',
            cookies: {},
            query: {},
            headers: { 'x-device-fingerprint': 'fingerprint-A' }, // Machine A
            isStatic: false,
            rawReq: { headers: { accept: 'text/html' } }
        };
        vi.spyOn(engine, 'calculateFinalScore').mockReturnValueOnce(20);
        const challengeDecision = await engine.processRequest(originalRequestContext);
        const body = challengeDecision.body;
        const nonce = body.match(/const nonce = "(.*?)"/)[1];
        const cpuTarget = body.match(/const cpuTarget = BigInt\("0x" \+ "([0-9a-fA-F]+)"\)/)[1];
        const memDifficulty = parseInt(body.match(/const memDifficulty = (\d+)/)[1], 10);
        const challengeContext = await inMemoryStore.get(`secret:${nonce}`);

        // --- 2. Second request: Solution is submitted from "Machine B" ---
        // --- FIX: Simulate the client creating the baseBlock for the solver ---
        // The solver uses the fingerprint of the machine it's running on.
        const messageBase = `${nonce}:${challengeContext.clientSecret}:fingerprint-B:`;
        const baseBlock = new TextEncoder().encode(messageBase);

        const cpuSolution = await solveCpuTargetInline(baseBlock, cpuTarget, null);
        const memSeed = `${nonce}:${challengeContext.clientSecret}`;
        const memSolution = await solveMemory(memSeed, memDifficulty);

        const submissionRequestContext = {
            clientIp: '127.0.0.1',
            path: '/sensitive-data',
            cookies: {},
            query: {
                pow_type: 'cpu_mem',
                pow_nonce: nonce,
                pow_solution_cpu: String(cpuSolution),
                pow_solution_mem: String(memSolution),
                pow_fp: 'fingerprint-B' // <-- MISMATCH! Solved on a different machine.
            },
            headers: { 'x-device-fingerprint': 'fingerprint-B' }, // Machine B
            isStatic: false,
            rawReq: { headers: { accept: 'text/html' } }
        };

        const validationDecision = await engine.processRequest(submissionRequestContext);

        // Assert: The solution is invalid due to fingerprint mismatch.
        // The score should be recalculated with a high honeypotScore.
        // Depending on the final score, the user is either blocked or re-challenged.
        // Here, we expect a block because honeypotScore has a weight of 1.0.
        expect(validationDecision.action).toBe('block');
        expect(validationDecision.score).toBeGreaterThanOrEqual(95);
        expect(validationDecision.vector.honeypotScore).toBe(100);

        // Assert: The challenge secret is NOT deleted, as the challenge failed.
        // The logic will re-challenge, but the test shows the invalidation path.
        // Note: In the actual implementation, the flow continues and might issue a new challenge,
        // but the key is that the `redirect` action was not taken.
    }, 20000);
});