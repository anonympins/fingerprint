import { describe, it, beforeEach } from 'vitest';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
    AppleAppAttestValidator,
    PlayIntegrityValidator,
    DbscSessionManager,
    HardwareAttestationManager
} from '../hardware-attestation.js';

describe('Attestation cryptographique matérielle', () => {
    let ecKeyPair;
    let ecJwk;
    let mockStore;

    beforeEach(() => {
        ecKeyPair = crypto.generateKeyPairSync('ec', {
            namedCurve: 'prime256v1'
        });
        ecJwk = ecKeyPair.publicKey.export({ format: 'jwk' });

        const map = new Map();
        mockStore = {
            get: async (key) => map.get(key) || null,
            set: async (key, val) => map.set(key, val),
            delete: async (key) => map.delete(key)
        };
    });

    const base64UrlEncode = (buf) =>
        buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    describe('Apple App Attest (Secure Enclave)', () => {
        it('valide une assertion conforme et met à jour le compteur monotone', () => {
            const storedCounter = 42;
            const nextCounter = 43;

            const authData = Buffer.alloc(37);
            authData.fill(0xbb, 0, 32); // rpIdHash
            authData[32] = 0x01;        // flags
            authData.writeUInt32BE(nextCounter, 33);

            const clientDataHash = crypto.createHash('sha256').update('sess1:127.0.0.1').digest();
            const signedData = Buffer.concat([authData, clientDataHash]);

            const signature = crypto.sign('sha256', signedData, ecKeyPair.privateKey);
            const assertionRaw = Buffer.concat([authData, signature]);

            const res = AppleAppAttestValidator.verifyAssertion(
                ecKeyPair.publicKey,
                assertionRaw,
                clientDataHash,
                storedCounter
            );

            assert.equal(res.isValid, true);
            assert.equal(res.newCounter, nextCounter);
        });

        it('rejette une assertion ayant un compteur inférieur ou égal au compteur stocké', () => {
            const storedCounter = 50;
            const staleCounter = 50; // Replay attack

            const authData = Buffer.alloc(37);
            authData.writeUInt32BE(staleCounter, 33);
            const clientDataHash = crypto.createHash('sha256').update('sess1:127.0.0.1').digest();
            const signature = crypto.sign('sha256', Buffer.concat([authData, clientDataHash]), ecKeyPair.privateKey);

            const res = AppleAppAttestValidator.verifyAssertion(
                ecKeyPair.publicKey,
                Buffer.concat([authData, signature]),
                clientDataHash,
                storedCounter
            );

            assert.equal(res.isValid, false);
            assert.equal(res.newCounter, storedCounter);
        });
    });

    describe('Google Play Integrity (Titan M / Keystore)', () => {
        it('décode et valide un jeton JWS avec verdict MEETS_STRONG_INTEGRITY', () => {
            // Création d'un certificat X.509 autosigné pour simuler le signataire Google
            // En Node.js natif pour le test de validation du jeton
            const expectedNonce = 'google_nonce_check';
            const packageName = 'com.anonympins.mobile';

            const header = { alg: 'ES256', typ: 'JWT' };
            const payload = {
                requestDetails: {
                    nonce: expectedNonce,
                    timestampMillis: Date.now()
                },
                appIntegrity: {
                    packageName
                },
                deviceIntegrity: {
                    deviceRecognitionVerdict: ['MEETS_STRONG_INTEGRITY']
                }
            };

            const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
            const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
            const signingInput = `${encodedHeader}.${encodedPayload}`;
            const sig = crypto.sign('sha256', Buffer.from(signingInput), ecKeyPair.privateKey);
            const jws = `${signingInput}.${base64UrlEncode(sig)}`;

            const res = PlayIntegrityValidator.decodeAndVerifyJws(jws, packageName, expectedNonce);

            assert.equal(res.isValid, true);
            assert.equal(res.payload.appIntegrity.packageName, packageName);
        });

        it('rejette un jeton Play Integrity si MEETS_STRONG_INTEGRITY est absent', () => {
            const header = { alg: 'ES256' };
            const payload = {
                requestDetails: { nonce: 'nonce1', timestampMillis: Date.now() },
                appIntegrity: { packageName: 'com.app' },
                deviceIntegrity: { deviceRecognitionVerdict: ['MEETS_BASIC_INTEGRITY'] } // Émulateur ou appareil rooté
            };

            const token = `${base64UrlEncode(Buffer.from(JSON.stringify(header)))}.${base64UrlEncode(Buffer.from(JSON.stringify(payload)))}.sig`;
            const res = PlayIntegrityValidator.decodeAndVerifyJws(token, 'com.app', 'nonce1');

            assert.equal(res.isValid, false);
        });
    });

    describe('Device Bound Session Credentials (DBSC - W3C TPM 2.0)', () => {
        it('valide avec succès la signature de possession du TPM', () => {
            const sessionId = 'dbsc_session_xyz';
            const origin = 'https://app.example.com';
            const nonce = 'dbsc_nonce_challenge';

            const header = { typ: 'dbsc+jwt', alg: 'ES256' };
            const payload = {
                sub: sessionId,
                aud: origin,
                nonce,
                exp: Math.floor(Date.now() / 1000) + 120
            };

            const headerEnc = base64UrlEncode(Buffer.from(JSON.stringify(header)));
            const payloadEnc = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
            const signingInput = `${headerEnc}.${payloadEnc}`;

            // Signature ECDSA P-256 standard IEEE P1363 (r || s, 64 octets)
            const derSig = crypto.sign('sha256', Buffer.from(signingInput), ecKeyPair.privateKey);

            const dbscJwt = `${signingInput}.${base64UrlEncode(derSig)}`;

            const isValid = DbscSessionManager.verifySessionProof(
                dbscJwt,
                ecJwk,
                sessionId,
                origin,
                nonce
            );

            assert.equal(isValid, true);
        });

        it('échoue si l\'audience ou le sujet de session ne correspondent pas', () => {
            const header = { typ: 'dbsc+jwt', alg: 'ES256' };
            const payload = {
                sub: 'legitimate_session',
                aud: 'https://attacker.com',
                exp: Math.floor(Date.now() / 1000) + 120
            };

            const signingInput = `${base64UrlEncode(Buffer.from(JSON.stringify(header)))}.${base64UrlEncode(Buffer.from(JSON.stringify(payload)))}`;
            const derSig = crypto.sign('sha256', Buffer.from(signingInput), ecKeyPair.privateKey);
            const dbscJwt = `${signingInput}.${base64UrlEncode(derSig)}`;

            const isValid = DbscSessionManager.verifySessionProof(
                dbscJwt,
                ecJwk,
                'victim_session', // Mismatch sub
                'https://legit.com' // Mismatch aud
            );

            assert.equal(isValid, false);
        });
    });

    describe('HardwareAttestationManager (Orchestrateur)', () => {
        it('accorde un verdict vérifié pour une requête DBSC TPM légitime', async () => {
            const manager = new HardwareAttestationManager(mockStore);
            const sessionId = 'session_tpm_1';
            const origin = 'https://portal.example.com';
            const nonce = 'nonce_dbsc_1';

            await mockStore.set(`dbsc-session:${sessionId}`, { jwk: ecJwk });
            await mockStore.set(`dbsc-nonce:${sessionId}`, nonce);

            const header = { typ: 'dbsc+jwt', alg: 'ES256' };
            const payload = { sub: sessionId, aud: origin, nonce, exp: Math.floor(Date.now() / 1000) + 60 };
            const signingInput = `${base64UrlEncode(Buffer.from(JSON.stringify(header)))}.${base64UrlEncode(Buffer.from(JSON.stringify(payload)))}`;
            const derSig = crypto.sign('sha256', Buffer.from(signingInput), ecKeyPair.privateKey);

            const context = {
                headers: {
                    'sec-session-response': `${signingInput}.${base64UrlEncode(derSig)}`
                }
            };

            const result = await manager.process(context, sessionId, '10.0.0.1', origin);

            assert.equal(result.verified, true);
            assert.equal(result.type, 'dbsc_tpm');
            assert.equal(await mockStore.get(`dbsc-nonce:${sessionId}`), null);
        });

        it('rejette quand aucun en-tête d\'attestation matérielle n\'est soumis', async () => {
            const manager = new HardwareAttestationManager(mockStore);
            const result = await manager.process({ headers: {} }, 's1', '127.0.0.1', 'https://example.com');

            assert.equal(result.verified, false);
            assert.equal(result.type, 'none');
        });
    });
});