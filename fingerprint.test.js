import { beforeEach, assert, describe, test, expect, vi } from 'vitest';
import crypto from 'node:crypto';
import * as fingerprint from './fingerprint.js';

const {
  cyrb53,
  isTicketValid,
  FingerprintBuilder,
  powMiddleware,
  __internal,
  configureStore,
  verifyCpuTargetPoWAndGenerateTicket,
  verifyMemoryPoW,
  verifyTspChallenge,
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

      await powMiddleware(securityConfig)(req, res, next);

      expect(next, 'next() should have been called').toHaveBeenCalled();
    });

    test('should issue a CPU challenge for a suspicious request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }); // finalScore = 25

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: vi.fn() // Mock cookie to prevent errors in getSuspicionVector
      };
      const next = vi.fn(() => { throw new Error('next() should not be called'); });

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

      await powMiddleware(securityConfig)(req, res, next);

      expect(sentStatus, 'Status should be 429').toBe(429);
      expect(sentBody, 'Should send a combined challenge page for medium suspicion').toContain('Enhanced Verification');
      expect(sentBody, 'Challenge should be the combined CPU+Mem type').toContain('Initializing combined verification...');
    });

    test('should issue a TSP challenge for a high-suspicion request', async () => {
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

      await powMiddleware(securityConfig)(req, res, next);

      expect(sentStatus, 'Status should be 429').toBe(429);
      expect(sentBody, 'Should send a high-level challenge page').toContain('Enhanced Verification');
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
      const req = { headers: { 'user-agent': 'test' }, cookies: {}, ip: '1.1.1.1', path: '/', query: {}, rawHeaders: ['User-Agent', 'test'] };
      const res = { cookie: vi.fn() };
      // Simulate a device using many IPs
      const deviceData = { initialDeviceHash: 'hash1', ips: new Set(['1.1.1.2', '1.1.1.3', '1.1.1.4', '1.1.1.5', '1.1.1.6']), lastUpdate: Date.now(), lastFpHash: 'hash1', lastChangeTimestamp: 0, rapidChangeCount: 0 };
      await inMemoryStore.set('device:test-device-id', deviceData);
      req.cookies.device_id = 'test-device-id';

      const vector = await __internal.getSuspicionVector(req, res);
      expect(vector.historyScore).toBeGreaterThan(20);
    });

  });
});