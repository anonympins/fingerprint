import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import * as fingerprint from './fingerprint.js';

const {
  cyrb53,
  isTicketValid,
  FingerprintBuilder,
  powMiddleware,
  __internal,
  verifyCpuTargetPoWAndGenerateTicket,
} = fingerprint;

test('Fingerprint & PoW Security Suite', async (t) => {
  await t.test('cyrb53 should be deterministic', () => {
    const input = "test-string";
    assert.strictEqual(cyrb53(input), cyrb53(input));
    assert.notStrictEqual(cyrb53("a"), cyrb53("b"));
  });

  await t.test('FingerprintBuilder comparison logic', () => {
    const fp1 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
    const fp2 = new FingerprintBuilder().add('hw', '8_16').add('gpu', 'nvidia').toString();
    const fp3 = new FingerprintBuilder().add('hw', '4_8').add('gpu', 'amd').toString();

    assert.strictEqual(FingerprintBuilder.compare(fp1, fp2), 1, "Identical FPs should return 1");
    assert.ok(FingerprintBuilder.compare(fp1, fp3) < 0.5, "Different FPs should have low similarity score");
  });

  await t.test('CPU Target PoW Workflow: Solve, Verify, and Validate Ticket', () => {
    const ip = '127.0.0.1';
    const nonce = 'test-nonce';
    const suspicionFactor = 0.1; // Faible suspicion pour un test rapide

    // Simulation d'un solveur côté client
    let solution = 0;
    let hash = '';
    const target = __internal.calculateTarget(suspicionFactor);

    while (true) {
      hash = crypto.createHash('sha256').update(`${ip}:${nonce}:${solution}`).digest('hex');
      if (BigInt('0x' + hash) < target) break;
      solution++;
    }

    // 1. Vérification de la solution et génération du ticket
    const ticket = verifyCpuTargetPoWAndGenerateTicket(ip, nonce, solution, suspicionFactor);
    assert.ok(ticket, "Le ticket devrait être généré pour une solution valide");

    // 2. Validation du ticket
    assert.ok(isTicketValid(ip, ticket), "Le ticket devrait être valide pour la même IP");

    // 3. Cas d'échec : Mauvaise IP
    assert.strictEqual(isTicketValid('1.1.1.1', ticket), false, "Le ticket ne doit pas être valide pour une IP différente");

    // 4. Cas d'échec : Solution invalide
    const badTicket = verifyCpuTargetPoWAndGenerateTicket(ip, nonce, "mauvaise-solution", suspicionFactor);
    assert.strictEqual(badTicket, null, "Une mauvaise solution ne doit pas produire de ticket");
  });

  await t.test('PoW Ticket Expiration', () => {
    const ip = '127.0.0.1';
    // On simule un ticket expiré en manipulant la chaîne (pour le test)
    const expiredTimestamp = Date.now() - 1000;
    const signature = crypto.createHmac("sha256", process.env.POW_SECRET || "fallback-dev-secret-32-chars-minimum").update(`${ip}:${expiredTimestamp}`).digest("hex");
    const ticket = `${expiredTimestamp}:${signature}`;
    assert.strictEqual(isTicketValid(ip, ticket), false, "Un ticket expiré doit être refusé");
  });

  await t.test('powMiddleware', async (t) => {
    const securityConfig = {
      weights: { historyScore: 1, rotationScore: 1, headerAnomalyScore: 1, inconsistencyScore: 1 },
      thresholds: { low: 20, medium: 45, high: 75 }
    };
    const middleware = powMiddleware(securityConfig);

    await t.test('should call next() for a non-suspicious request', async () => {
      t.mock.method(__internal, 'getSuspicionVector', () => Promise.resolve({
        historyScore: 0, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }));
        let sentStatus, sentBody;

        const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      const res = { cookie: () => {}, status: (s) => { sentStatus = s; return res; }, send: (b) => { sentBody = b; } }; // Add a mock cookie function
      let nextCalled = false;
      const next = () => { nextCalled = true; };

      await middleware(req, res, next);

      assert.ok(nextCalled, 'next() should have been called');
    });

    await t.test('should issue a CPU challenge for a suspicious request', async () => {
      t.mock.method(__internal, 'getSuspicionVector', () => Promise.resolve({
        historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }));

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: () => {} // Mock cookie to prevent errors in getSuspicionVector
      };
      const next = () => { assert.fail('next() should not be called'); };

      await middleware(req, res, next);

      assert.strictEqual(sentStatus, 429, 'Status should be 429');
      assert.ok(sentBody.includes('Security Check'), 'Should send a challenge page');
      assert.ok(sentBody.includes('cpu_target'), 'Challenge should be of type cpu_target');
    });
    // In the test above, I've added a mock `cookie` function to the `res` object.
    // I also adjusted how `sentStatus` and `sentBody` are captured to avoid potential closure issues, though the original way was likely fine.

    await t.test('should issue a Memory challenge for a medium-suspicious request', async () => {
      t.mock.method(__internal, 'getSuspicionVector', () => Promise.resolve({
        historyScore: 50, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }));

      const req = { path: '/', ip: '127.0.0.1', cookies: {}, query: {}, headers: { 'user-agent': 'test-ua' } };
      let sentStatus, sentBody;
      const res = {
        status: (s) => { sentStatus = s; return res; },
        send: (b) => { sentBody = b; },
        cookie: () => {} // Mock cookie to prevent errors in getSuspicionVector
      };
      const next = () => { assert.fail('next() should not be called'); };

      await middleware(req, res, next);

      assert.strictEqual(sentStatus, 429, 'Status should be 429');
      assert.ok(sentBody.includes('Vérification renforcée'), 'Should send a medium challenge page');
      assert.ok(sentBody.includes('Allocation et calcul mémoire'), 'Challenge should be of type memory');
    });

    await t.test('should call next() for a suspicious request with a valid ticket', async () => {
      t.mock.method(__internal, 'getSuspicionVector', () => Promise.resolve({
        historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0
      }));

      const ip = '127.0.0.1';
      const expiry = Date.now() + 3600000;
      const signature = crypto.createHmac("sha256", process.env.POW_SECRET || "fallback-dev-secret-32-chars-minimum").update(`${ip}:${expiry}`).digest("hex");
      const validTicket = `${expiry}:${signature}`;

      const req = { path: '/', ip, cookies: { pow_clearance: validTicket }, query: {}, headers: { 'user-agent': 'test-ua' } };
      const res = { cookie: () => {} }; // Add a mock cookie function
      let nextCalled = false;
      const next = () => { nextCalled = true; };

      await middleware(req, res, next);

      assert.ok(nextCalled, 'next() should have been called for a request with a valid ticket');
    });

    await t.test('should redirect after a valid PoW solution is provided', async () => {
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

      t.mock.method(__internal, 'getSuspicionVector', () => Promise.resolve({ historyScore: 25, rotationScore: 0, headerAnomalyScore: 0, inconsistencyScore: 0 }));
      const req = { path: '/protected', ip, cookies: {}, query: { pow_type: 'cpu_target', pow_nonce: nonce, pow_solution: solution }, headers: { 'user-agent': 'test-ua' } };
      let redirectedTo, cookieName, cookieValue;
      const res = { cookie: (n, v) => { cookieName = n; cookieValue = v; }, redirect: (p) => { redirectedTo = p; } };
      const next = () => { assert.fail('next() should not be called'); };

      await middleware(req, res, next);

      assert.strictEqual(redirectedTo, '/protected', 'Should redirect to the original path');
      assert.strictEqual(cookieName, 'pow_clearance', 'Should set the clearance cookie');
      assert.ok(isTicketValid(ip, cookieValue), 'The set cookie should be valid');
    });
  });
});