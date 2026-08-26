import { solveCpuTargetInline } from '../pow.solver.js';
import { webcrypto } from 'node:crypto';

// Simule l'API Web Crypto qui n'est pas disponible par défaut dans Node.js avant la v15.7.0
if (typeof global.crypto === 'undefined') {
  global.crypto = webcrypto;
}

describe('Proof-of-Work Solvers', () => {

  describe('solveCpuTargetInline', () => {

    // Teste le cas où un `clientSecret` est utilisé. C'est le cas qui posait problème.
    it('should correctly hash the message including the clientSecret and fingerprint', async () => {
      const nonce = 'test-nonce';
      const clientSecret = 'test-secret';
      const fingerprint = 'fp-string-123';
      // Cible très facile à atteindre pour que le test soit rapide (solution = 0)
      const target = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

      // On espionne `crypto.subtle.digest` pour voir avec quoi il est appelé.
      const digestSpy = vi.spyOn(global.crypto.subtle, 'digest');

      const solution = await solveCpuTargetInline(null, nonce, target, clientSecret, null, fingerprint);

      // La solution devrait être 0 car la première tentative réussit.
      expect(solution).toBe(0);

      // On vérifie que le message haché est dans le bon format.
      const expectedMessage = `${nonce}:${solution}:${clientSecret}:${fingerprint}`;
      
      // `digest` est appelé avec un ArrayBuffer, on le décode pour le comparer.
      const actualMessage = new TextDecoder().decode(digestSpy.mock.calls[0][1]);

      expect(actualMessage).toBe(expectedMessage);

      // Nettoie l'espion
      digestSpy.mockRestore();
    });

    // Teste le cas de secours sans `clientSecret`.
    it('should correctly hash the message with IP when clientSecret is not provided', async () => {
      const clientIp = '127.0.0.1';
      const nonce = 'test-nonce-2';
      const fingerprint = 'fp-string-456'; // Le fingerprint ne doit pas être inclus dans ce cas.
      const target = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

      const digestSpy = vi.spyOn(global.crypto.subtle, 'digest');

      const solution = await solveCpuTargetInline(clientIp, nonce, target, null, null, fingerprint);

      expect(solution).toBe(0);

      // Le message ne doit PAS contenir le secret ni le fingerprint.
      const expectedMessage = `${clientIp}:${nonce}:${solution}`;
      const actualMessage = new TextDecoder().decode(digestSpy.mock.calls[0][1]);

      expect(actualMessage).toBe(expectedMessage);

      digestSpy.mockRestore();
    });
  });

});