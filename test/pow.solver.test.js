import { solveCpuTargetInline } from '../pow.solver.js';
import { webcrypto } from 'node:crypto';

// Simule l'API Web Crypto qui n'est pas disponible par défaut dans Node.js avant la v15.7.0
if (typeof global.crypto === 'undefined') {
  global.crypto = webcrypto;
}

describe('Proof-of-Work Solvers', () => {

  describe('solveCpuTargetInline', () => {

    it('should correctly hash the final block based on the provided baseBlock', async () => {
      const nonce = 'test-nonce';
      const clientSecret = 'test-secret';
      const fingerprint = 'fp-string-123|another-part-456';
      // Cible très facile à atteindre pour que le test soit rapide (solution = 0)
      const target = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');

      // 1. Construire le message de base comme le ferait le serveur.
      // Le fingerprint est trié pour être déterministe.
      const sortedFingerprint = fingerprint.split('|').sort().join('|');
      const messageBase = `${nonce}:${clientSecret}:${sortedFingerprint}:`;
      const baseBlock = new TextEncoder().encode(messageBase);

      // On espionne `crypto.subtle.digest` pour voir avec quoi il est appelé.
      const digestSpy = vi.spyOn(global.crypto.subtle, 'digest');

      // 2. Appeler la fonction avec la nouvelle signature.
      const solution = await solveCpuTargetInline(baseBlock, target, null);

      // La solution devrait être 0 car la première tentative réussit.
      expect(solution).toBe(0);

      // 3. Vérifier que le bloc final passé au hachage est correct.
      // Il doit être `baseBlock` + `solution`.
      const expectedFinalMessage = `${messageBase}${solution}`;
      const actualFinalMessage = new TextDecoder().decode(digestSpy.mock.calls[0][1]);

      expect(actualFinalMessage).toBe(expectedFinalMessage);

      // Nettoie l'espion
      digestSpy.mockRestore();
    });

    it('should find a solution for a non-trivial target', async () => {
      const nonce = 'test-nonce-2';
      // Cible qui nécessite quelques itérations (les 8 premiers bits à 0)
      const target = 2n ** 248n; // '00' + 62 'f'

      // Construire un baseBlock simple pour ce test.
      const messageBase = `${nonce}::fp-simple:`; // secret et partie du fp vides
      const baseBlock = new TextEncoder().encode(messageBase);

      const solution = await solveCpuTargetInline(baseBlock, target, null);

      // La solution ne sera pas 0.
      expect(solution).toBeGreaterThan(0);

      // Vérification côté "serveur" que la solution est valide.
      const finalBlock = new TextEncoder().encode(`${messageBase}${solution}`);
      const hashBuffer = await global.crypto.subtle.digest('SHA-256', finalBlock);
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      expect(BigInt('0x' + hashHex)).toBeLessThan(target);
    });
  });

});