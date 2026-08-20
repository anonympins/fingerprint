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
} = fingerprint;

describe('Fingerprint & PoW Security Suite', () => {
  test('cyrb53 should be deterministic', () => {
    const input = "test-string";
    expect(cyrb53(input)).toBe(cyrb53(input));
    expect(cyrb53("a")).not.toBe(cyrb53("b"));
  });

  test('FingerprintBuilder comparison logic', () => {
    const fp1 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
    const fp2 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
    const fp3 = new FingerprintBuilder().add('hw', '4_8').add('gpu', 'amd').toString();

    expect(FingerprintBuilder.compare(fp1, fp2), "Identical FPs should return 1").toBe(1);
    expect(FingerprintBuilder.compare(fp1, fp3), "Different FPs should have low similarity score").toBeLessThan(0.5);
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
      });

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
      assert.ok(sentBody.includes('Enhanced Verification'), 'Should send a combined challenge page for low suspicion');
      assert.ok(sentBody.includes('Initializing combined verification...'), 'Challenge should be the combined CPU+Mem type');
    });

    test('should issue a Memory challenge for a medium-suspicious request', async () => {
      vi.spyOn(__internal, 'getSuspicionVector').mockResolvedValue({
        historyScore: 50, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      });

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
});