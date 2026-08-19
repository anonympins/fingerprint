import test from 'node:test';
import assert from 'node:assert';
import crypto from 'node:crypto';
import { 
  cyrb53, 
  verifyPoWAndGenerateTicket, 
  isTicketValid, 
  FingerprintBuilder 
} from './fingerprint.js';

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

  await t.test('PoW Workflow: Solve, Verify, and Validate Ticket', () => {
    const ip = '127.0.0.1';
    const nonce = 'test-nonce';
    const difficulty = 2; // Basse difficulté pour le test
    const target = '0'.repeat(difficulty);
    
    // Simulation d'un solveur côté client
    let solution = 0;
    let hash = '';
    while (true) {
      hash = crypto.createHash('sha256').update(`${ip}:${nonce}:${solution}`).digest('hex');
      if (hash.startsWith(target)) break;
      solution++;
    }

    // 1. Vérification de la solution et génération du ticket
    const ticket = verifyPoWAndGenerateTicket(ip, nonce, solution, difficulty);
    assert.ok(ticket, "Le ticket devrait être généré pour une solution valide");

    // 2. Validation du ticket
    assert.ok(isTicketValid(ip, ticket), "Le ticket devrait être valide pour la même IP");
    
    // 3. Cas d'échec : Mauvaise IP
    assert.strictEqual(isTicketValid('1.1.1.1', ticket), false, "Le ticket ne doit pas être valide pour une IP différente");

    // 4. Cas d'échec : Solution invalide
    const badTicket = verifyPoWAndGenerateTicket(ip, nonce, "mauvaise-solution", difficulty);
    assert.strictEqual(badTicket, null, "Une mauvaise solution ne doit pas produire de ticket");
  });

  await t.test('PoW Ticket Expiration', () => {
    const ip = '127.0.0.1';
    // On simule un ticket expiré en manipulant la chaîne (pour le test)
    const expiredTimestamp = Date.now() - 1000;
    const ticket = `${expiredTimestamp}:some-sig`;
    assert.strictEqual(isTicketValid(ip, ticket), false, "Un ticket expiré doit être refusé");
  });
});