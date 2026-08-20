import { beforeEach, afterEach, assert, describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import * as fingerprint from './fingerprint.js';
import * as fingerprintServer from './fingerprint.server.js';
import { FingerprintBuilder, cyrb53 } from './fingerprint.builder.js';

const {
  isTicketValid,
  identifyRequest,
  powMiddleware,
  __internal,
  configureStore,
  verifyCpuTargetPoWAndGenerateTicket,
  verifyMemoryPoW,
  verifyTspChallenge,
  startThresholdAutoTuning,
  stopThresholdAutoTuning,
} = fingerprint;

describe('Fingerprint & PoW Security Suite', () => {
  test('cyrb53 should be deterministic', () => {
    const input = "test-string";
    expect(cyrb53(input)).toBe(cyrb53(input));
    expect(cyrb53("a")).not.toBe(cyrb53("b"));
  });

  describe('FingerprintBuilder', () => {
    test('should handle null and undefined values gracefully', () => {
      const builder = new FingerprintBuilder();
      builder.add('key1', 'value1');
      builder.add('key2', null);
      builder.add('key3', undefined);
      expect(builder.toString()).toBe('key1:6263243896157005');
    });

    test('comparison logic should handle various cases', () => {
      const fp1 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
      const fp2 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
      const fp3 = new FingerprintBuilder().add('hw', '4_8').add('gpu', 'amd').toString();
      const fp4 = new FingerprintBuilder().add('hw', '8_16').add('os', 'win32').toString(); // Partial match

      expect(FingerprintBuilder.compare(fp1, fp2), "Identical FPs should return 1").toBe(1);
      expect(FingerprintBuilder.compare(fp1, fp3), "Different FPs should have low similarity score").toBeLessThan(0.5);
      expect(FingerprintBuilder.compare(fp1, fp4), "Partial match should return a score between 0 and 1").toBeGreaterThan(0);
      expect(FingerprintBuilder.compare(fp1, fp4)).toBeLessThan(1);
      expect(FingerprintBuilder.compare(fp1, ''), "Comparison with empty string should be 0").toBe(0);
      expect(FingerprintBuilder.compare(null, fp2), "Comparison with null should be 0").toBe(0);
    });
  });

  test('CPU Target PoW Workflow: Solve, Verify, and Validate Ticket', () => {
    const ip = '127.0.0.1';
    const nonce = 'test-nonce';
    const suspicionFactor = 0.1; // Low suspicion for a quick test

    // Simulation d'un solveur côté client
    let solution = 0;
    let hash = '';
    const target = __internal.calculateTarget(suspicionFactor);

    while (true) {
      hash = crypto.createHash('sha256').update(`${ip}:${nonce}:${solution}`).digest('hex');
      if (BigInt('0x' + hash) < target) break;
      solution++;
    }

    // 1. Verify the solution and generate the ticket
    const ticket = verifyCpuTargetPoWAndGenerateTicket(ip, nonce, solution, suspicionFactor);
    expect(ticket, "Ticket should be generated for a valid solution").toBeTruthy();

    // 2. Validate the ticket
    expect(isTicketValid(ip, ticket), "Ticket should be valid for the same IP").toBe(true);

    // 3. Failure case: Wrong IP
    expect(isTicketValid('1.1.1.1', ticket), "Ticket should not be valid for a different IP").toBe(false);

    // 4. Failure case: Invalid solution
    const badTicket = verifyCpuTargetPoWAndGenerateTicket(ip, nonce, "mauvaise-solution", suspicionFactor);
    expect(badTicket, "A bad solution should not produce a ticket").toBeNull();
  });

  test('PoW Ticket Expiration', () => {
    const ip = '127.0.0.1';
    // Simulate an expired ticket by manipulating the string (for testing)
    const expiredTimestamp = Date.now() - 1000;
    const signature = crypto.createHmac("sha256", process.env.POW_SECRET || "fallback-dev-secret-32-chars-minimum").update(`${ip}:${expiredTimestamp}`).digest("hex");
    const ticket = `${expiredTimestamp}:${signature}`;
    expect(isTicketValid(ip, ticket), "An expired ticket should be rejected").toBe(false);
  });

  test('Memory PoW Verification', () => {
    const nonce = 'test-nonce-mem';
    const difficulty = 1; // 1MB for a quick test

    // Client-side simulation
    const size = difficulty * 1024 * 1024;
    const buffer = new Uint32Array(size / 4);
    let h = new TextEncoder().encode(nonce).reduce((acc, v) => acc + v, 0);
    for (let i = 0; i < buffer.length; i++) {
        buffer[i] = (h = Math.imul(h ^ i, 1597334677));
    }
    let clientSolution = 0;
    for(let i = 0; i < (size / 16); i++) {
        const addr = buffer[i % buffer.length] % buffer.length;
        clientSolution ^= buffer[addr];
    }

    // Server-side verification
    expect(verifyMemoryPoW(nonce, String(clientSolution), difficulty), "Valid memory PoW solution should be accepted").toBe(true);
    expect(verifyMemoryPoW(nonce, String(clientSolution + 1), difficulty), "Invalid memory PoW solution should be rejected").toBe(false);
  });

  test('TSP Challenge Verification', () => {
    const nonce = 'test-nonce-tsp';
    const cities = [{x: 10, y: 10}, {x: 90, y: 90}, {x: 10, y: 90}, {x: 90, y: 10}];
    const numCities = cities.length;
    const targetMaxDistance = 350; // A reasonable target for this square

    // A valid, optimal path for this square is [0, 2, 1, 3] or similar
    const validSolution = JSON.stringify([0, 2, 1, 3]);
    // An invalid path (not a permutation)
    const invalidPermutation = JSON.stringify([0, 1, 1, 2]);
    // A valid path, but likely too long
    const suboptimalSolution = JSON.stringify([0, 1, 2, 3]);

    expect(verifyTspChallenge(nonce, validSolution, numCities, targetMaxDistance, cities), "A valid TSP solution should be accepted").toBe(true);
    expect(verifyTspChallenge(nonce, invalidPermutation, numCities, targetMaxDistance, cities), "A TSP solution that is not a permutation should be rejected").toBe(false);
    
    // This test assumes the simple path is longer than the target.
    const isSuboptimalRejected = !verifyTspChallenge(nonce, suboptimalSolution, numCities, targetMaxDistance, cities);
    if (isSuboptimalRejected) {
      expect(true, "A suboptimal TSP solution (too long) should be rejected").toBe(true);
    }
  });

  describe('identifyRequest (for Rate Limiting)', () => {
    const inMemoryStore = {
      _map: new Map(),
      get: async (key) => inMemoryStore._map.get(key),
      set: async (key, value) => inMemoryStore._map.set(key, value),
      has: async (key) => inMemoryStore._map.has(key),
      delete: async (key) => inMemoryStore._map.delete(key),
    };
    const securityConfig = {
      weights: { historyScore: 0.3, rotationScore: 0.5, headerAnomalyScore: 0.4, inconsistencyScore: 0.8 },
      thresholds: { low: 20, medium: 35, high: 75 }
    };
    let engine;

    beforeEach(() => {
      inMemoryStore._map.clear();
      configureStore(inMemoryStore);
      vi.restoreAllMocks();
      engine = new __internal.FingerprintEngine(securityConfig);
    });

    test('should return a device-specific key for a normal request', async () => {
      const requestContext = { 
        clientIp: '127.0.0.1', 
        cookies: {}, 
        headers: {
          'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
          'accept-language': 'en-US,en;q=0.9',
          'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }, 
        rawHeaders: ['User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36', 'Accept-Language', 'en-US,en;q=0.9', 'Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'], 
        httpVersion: '1.1' };
      const key = await engine.identifyRequest(requestContext);
      expect(key).toMatch(/^device:/);
    });

    test('should return a suspicion-based key for a highly suspicious request', async () => {
      // This context simulates a request from a simple script (e.g., curl) with missing headers.
      const requestContext = {
        clientIp: '127.0.0.1',
        cookies: {},
        headers: {}, // Simulate completely missing headers
        rawHeaders: [],
        httpVersion: '1.1'
      };
      const key = await engine.identifyRequest(requestContext);
      // Missing accept/accept-language headers should trigger a medium suspicion score.
      expect(key).toBe('suspicious_medium:127.0.0.1');
    });
  });

  test('getDeviceHash should prioritize client-side fingerprint header', async () => {
    // 1. Spy on the getDeviceHash function from its actual module
    const getDeviceHashSpy = vi.spyOn(fingerprintServer, 'getDeviceHash');

    // 2. Simulate a request context with the special header
    const clientSideFingerprint = 'cvs:12345|gpu:67890|hw:stable';
    const requestContext = {
      headers: {
        'user-agent': 'A regular user agent',
        'x-device-fingerprint': clientSideFingerprint,
      },
      // ... other context properties
    };

    // 3. Call the function and assert it returns the client-side FP
    const result = fingerprintServer.getDeviceHash(requestContext);

    expect(result).toBe(clientSideFingerprint);
    expect(getDeviceHashSpy).toHaveBeenCalledWith(requestContext);
  });

  describe('powMiddleware', () => {
    // Mock store for tests
    const inMemoryStore = {
      _map: new Map(),
      async get(key) { return this._map.get(key); },
      async set(key, value) { this._map.set(key, value); },
      async has(key) { return this._map.has(key); },
      async delete(key) { this._map.delete(key); },
    };
    beforeEach(() => {
      inMemoryStore._map.clear();
      configureStore(inMemoryStore);
      vi.restoreAllMocks();
    });

    const securityConfig = {
      weights: { historyScore: 1, rotationScore: 1, headerAnomalyScore: 1, inconsistencyScore: 1 },
      thresholds: { low: 20, medium: 45, high: 75 }
    };

    test('should call next() for a non-suspicious request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 0, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      });

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      const res = { cookie: vi.fn(), status: vi.fn().mockReturnThis(), send: vi.fn() };
      const next = vi.fn();

      req.fingerprint = {}; // Middleware would initialize this
      await powMiddleware(securityConfig)(req, res, next);

      expect(next, 'next() should have been called').toHaveBeenCalled();
    });

    test('should issue a CPU challenge for a suspicious request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }); // finalScore = 25

      const req = {
        path: '/',
        ip: '127.0.0.1',
        cookies: {},
        query: {},
        headers: { 'user-agent': 'test-ua' },
        rawHeaders: ['User-Agent', 'test-ua'], httpVersion: '1.1' };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: vi.fn() // Mock cookie to prevent errors in getSuspicionVector
      };
      const next = vi.fn(() => { throw new Error('next() should not be called'); });

      req.fingerprint = {};
      await powMiddleware(securityConfig)(req, res, next);

      assert.strictEqual(sentStatus, 429, 'Status should be 429');
      assert.ok(sentBody.includes('Enhanced Verification'), 'Should send a combined challenge page even for low suspicion');
      assert.ok(sentBody.includes('Initializing combined verification...'), 'Challenge should always be the combined CPU+Mem type');
    });

    test('should issue a Memory challenge for a medium-suspicious request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 50, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }); // finalScore = 50

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: vi.fn() // Mock cookie to prevent errors in getSuspicionVector
      };
      const next = vi.fn(() => { throw new Error('next() should not be called'); });

      req.fingerprint = {};
      await powMiddleware(securityConfig)(req, res, next);

      expect(sentStatus, 'Status should be 429').toBe(429);
      expect(sentBody, 'Should send a combined challenge page for medium suspicion').toContain('Enhanced Verification');
      expect(sentBody, 'Challenge should be the combined CPU+Mem type').toContain('Initializing combined verification...');
    });

    test('should issue a high-difficulty combined challenge for a high-suspicion request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 80, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }); // finalScore = 80

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: vi.fn()
      };
      const next = vi.fn(() => { throw new Error('next() should not be called'); });

      req.fingerprint = {};
      await powMiddleware(securityConfig)(req, res, next);

      expect(sentStatus, 'Status should be 429').toBe(429);
      expect(sentBody, 'Should send a combined challenge page for high suspicion').toContain('Enhanced Verification');
    });

    test('should call next() for a suspicious request with a valid ticket', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      });

      const ip = '127.0.0.1';
      const expiry = Date.now() + 3600000;
      const signature = crypto.createHmac("sha256", process.env.POW_SECRET || "fallback-dev-secret-32-chars-minimum").update(`${ip}:${expiry}`).digest("hex");
      const validTicket = `${expiry}:${signature}`;

      const req = { path: '/', ip, cookies: { pow_clearance: validTicket }, query: {}, headers: { 'user-agent': 'test-ua' } };
      const res = { cookie: vi.fn() };
      const next = vi.fn();

      req.fingerprint = {};
      await powMiddleware(securityConfig)(req, res, next);

      expect(next, 'next() should have been called for a request with a valid ticket').toHaveBeenCalled();
    });

    test('should redirect after a valid PoW solution is provided', async () => {
      const ip = '127.0.0.1';
      const nonce = 'test-nonce-redirect';
      const suspicionFactor = 0.1;
      const target = __internal.calculateTarget(suspicionFactor);
      let solution = 0;
      while (true) {
        const hash = crypto.createHash('sha256').update(`${ip}:${nonce}:${solution}`).digest('hex');
        if (BigInt('0x' + hash) < target) break;
        solution++;
      }

      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({ historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0 });
      const req = { path: '/protected', ip, cookies: {}, query: { pow_type: 'cpu_target', pow_nonce: nonce, pow_solution: solution }, headers: { 'user-agent': 'test-ua' } };
      let redirectedTo, cookieName, cookieValue;
      const res = { cookie: (n, v) => { cookieName = n; cookieValue = v; }, redirect: (p) => { redirectedTo = p; } };
      const next = vi.fn(() => { throw new Error('next() should not be called'); });

      req.fingerprint = {};
      await powMiddleware(securityConfig)(req, res, next);

      expect(redirectedTo, 'Should redirect to the original path').toBe('/protected');
      expect(cookieName, 'Should set the clearance cookie').toBe('pow_clearance');
      expect(isTicketValid(ip, cookieValue), 'The set cookie should be valid').toBe(true);
    });
  });

  describe('Suspicion Scoring Logic (Integration)', () => {
    const inMemoryStore = {
      _map: new Map(),
      async get(key) { return this._map.get(key); },
      async set(key, value) { this._map.set(key, value); },
    };
    beforeEach(() => {
      inMemoryStore._map.clear();
      configureStore(inMemoryStore);
    });

    test('should produce a high historyScore for rapid IP rotation', async () => {
      const req = { 
        headers: { 
          'user-agent': 'test',
          'x-device-fingerprint': 'cvs:123|gpu:456|hw:789' // Simulate client-side FP
        }, 
        cookies: {}, ip: '1.1.1.1', path: '/', query: {}, rawHeaders: ['User-Agent', 'test'] 
      };
      const res = { cookie: vi.fn() };
      // Simulate a device using many IPs
      const deviceData = { initialDeviceHash: 'hash1', ips: new Set(['1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5', '1.1.1.6']), lastUpdate: Date.now(), lastFpHash: 'hash1', lastChangeTimestamp: 0, rapidChangeCount: 0 };
      await inMemoryStore.set('device:test-device-id', deviceData);
      req.cookies.device_id = 'test-device-id';

      const vector = await __internal.getSuspicionVector(req, res);
      expect(vector.historyScore).toBeGreaterThan(20);
    });

  });

  describe('Client-Side Functions', () => {
    // Mock browser environment for client-side functions
    const mockWindow = {
      navigator: {
        hardwareConcurrency: 8,
        deviceMemory: 8,
        maxTouchPoints: 0,
        platform: 'Win32',
        webdriver: false,
        language: 'en-US',
      },
      screen: {
        width: 1920,
        height: 1080,
        colorDepth: 24,
      },
      document: {
        createElement: vi.fn().mockImplementation((tag) => {
          if (tag === "canvas") {
            const canvasMock = {
              width: 0,
              height: 0,
              getContext: vi.fn((contextType) => {
                if (contextType === "2d") {
                  return {
                    // These are for the 2D context
                    fillRect: vi.fn(),
                    fillText: vi.fn(),
                    toDataURL: vi
                      .fn()
                      .mockReturnValue("data:image/png;base64,mock-canvas-data"),
                  };
                }
                if (
                  contextType === "webgl" ||
                  contextType === "experimental-webgl"
                ) {
                  // These are for the WebGL context
                  return {
                    getExtension: vi.fn().mockReturnValue({
                      UNMASKED_VENDOR_WEBGL: "vendor_id",
                      UNMASKED_RENDERER_WEBGL: "renderer_id",
                    }),
                  };
                }
                return null;
              }),
            };
            return canvasMock;
          }
          return {};
        }),
      },
      Intl: {
        DateTimeFormat: () => ({
          resolvedOptions: () => ({ timeZone: 'Europe/Paris' }),
        }),
      },
      crypto: {
        subtle: {
          importKey: vi.fn().mockResolvedValue('mock-key'),
          sign: vi.fn().mockResolvedValue(new ArrayBuffer(32)), // Mock 32-byte signature
        }
      }
    };

    let clientFunctions;

    beforeEach(async () => {
      // Use vi.stubGlobal to mock browser environment, compatible with newer Node versions
      vi.stubGlobal('window', mockWindow);
      vi.stubGlobal('document', mockWindow.document);
      vi.stubGlobal('navigator', mockWindow.navigator);
      vi.stubGlobal('screen', mockWindow.screen);
      vi.stubGlobal('Intl', mockWindow.Intl);
      (await import('./fingerprint.client.js'))._resetCache();
      // Dynamically import client functions to use the mocked environment
      clientFunctions = await import('./fingerprint.client.js');
    });

    afterEach(() => {
      mockWindow.document.createElement.mockClear();
      vi.restoreAllMocks();
    });

    test('getDeviceFingerprint should generate a fingerprint string', () => {
      const fp = clientFunctions.getDeviceFingerprint();
      expect(fp).toBeTypeOf('string');
      expect(fp).toContain('geo:');
      expect(fp).toContain('hw:');
      expect(fp).toContain('scr:');
    });
  });

  describe('Threshold Auto-Tuning', () => {
    let setIntervalSpy, clearIntervalSpy, consoleLogSpy;

    beforeEach(() => {
      setIntervalSpy = vi.spyOn(global, 'setInterval');
      clearIntervalSpy = vi.spyOn(global, 'clearInterval');
      consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    });
    afterEach(() => {
      vi.restoreAllMocks();
      stopThresholdAutoTuning(); // Ensure cleanup after each test
    });

    test('should start, run an optimization cycle, and update thresholds', () => {
      const trafficData = [];
      const securityConfig = {
        thresholds: { low: 50, medium: 70, high: 90 }, // Intentionally bad initial thresholds
        logger: (log) => trafficData.push(log),
      };

      // Generate mock data where optimal 'low' threshold is around 25
      // Bots with low scores (false negatives)
      for (let i = 0; i < 50; i++) trafficData.push({ type: 'challenge_issued', deviceId: `bot-${i}`, score: 15 + Math.random() * 5 });
      // Humans with slightly higher scores (false positives)
      for (let i = 0; i < 50; i++) trafficData.push({ type: 'request_passed', deviceId: `human-${i}`, score: 30 + Math.random() * 5 });
      // Solved challenges (clear humans)
      for (let i = 0; i < 20; i++) trafficData.push({ type: 'challenge_solved', deviceId: `human-solver-${i}`, score: 40 });


      startThresholdAutoTuning({
        securityConfig,
        trafficData,
        interval: 60000, // 1 minute
        minDataPoints: 100,
      });

      // Manually trigger the optimization cycle
      const intervalCallback = setIntervalSpy.mock.calls[0][0];
      intervalCallback();

      // The genetic algorithm should find better thresholds.
      // We expect 'low' to decrease significantly from 50.
      expect(securityConfig.thresholds.low).toBeLessThanOrEqual(40);
      expect(securityConfig.thresholds.low).toBeGreaterThanOrEqual(10);
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('[AutoTuning] Nouveaux seuils optimisés appliqués'), expect.anything());
      expect(setIntervalSpy).toHaveBeenCalledTimes(1);

      // Stop the tuner and check if the interval is cleared
      stopThresholdAutoTuning();
      expect(clearIntervalSpy).toHaveBeenCalled();
    });

    test('should not run optimization if data points are insufficient', () => {
      const trafficData = [];
      const securityConfig = {
        thresholds: { low: 20, medium: 45, high: 75 },
        logger: (log) => trafficData.push(log),
      };

      // Generate only 50 data points, less than the minimum of 100
      for (let i = 0; i < 50; i++) {
        trafficData.push({ type: 'request_passed', deviceId: `human-${i}`, score: 10 });
      }

      startThresholdAutoTuning({
        securityConfig,
        trafficData,
        interval: 60000,
        minDataPoints: 100,
      });

      // Manually trigger the cycle
      const intervalCallback = setIntervalSpy.mock.calls[0][0];
      intervalCallback();

      // Check that optimization was postponed
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('[AutoTuning] Reporté'));
      // Thresholds should not have changed
      expect(securityConfig.thresholds).toEqual({ low: 20, medium: 45, high: 75 });

      // Add more data to meet the threshold
      for (let i = 0; i < 50; i++) {
        trafficData.push({ type: 'request_passed', deviceId: `human-new-${i}`, score: 10 });
      }
      // Trigger again
      intervalCallback();
      expect(consoleLogSpy).toHaveBeenCalledWith(expect.stringContaining('[AutoTuning] Démarrage du cycle d\'optimisation'));
    });
  });
});