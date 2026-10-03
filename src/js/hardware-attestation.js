import crypto from "node:crypto";

/**
 * Décode de manière sécurisée une chaîne base64url en Buffer.
 * @param {string} str
 * @returns {Buffer}
 */
function base64UrlDecode(str) {
    if (!str || typeof str !== 'string') return Buffer.alloc(0);
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
        base64 += '=';
    }
    return Buffer.from(base64, 'base64');
}

/**
 * Convertit une signature ECDSA P-256 IEEE P1363 (r || s, 64 octets) au format DER ASN.1.
 * @param {Buffer} ieeeBuffer
 * @returns {Buffer}
 */
function ieeeP1363ToDer(ieeeBuffer) {
    if (ieeeBuffer.length !== 64) return ieeeBuffer;
    const r = ieeeBuffer.subarray(0, 32);
    const s = ieeeBuffer.subarray(32, 64);

    const encodeInt = (buf) => {
        let start = 0;
        while (start < buf.length && buf[start] === 0) start++;
        let slice = buf.subarray(start);
        if (slice.length === 0) slice = Buffer.from([0]);
        if (slice[0] & 0x80) {
            slice = Buffer.concat([Buffer.from([0]), slice]);
        }
        return Buffer.concat([Buffer.from([0x02, slice.length]), slice]);
    };

    const rDer = encodeInt(r);
    const sDer = encodeInt(s);
    const seqLen = rDer.length + sDer.length;
    return Buffer.concat([Buffer.from([0x30, seqLen]), rDer, sDer]);
}

/**
 * Validateur pour Apple App Attest (Secure Enclave).
 */
export class AppleAppAttestValidator {
    /**
     * Vérifie une assertion émise par le Secure Enclave.
     * @param {crypto.KeyObject|string|Buffer} publicKey
     * @param {Buffer} assertionRaw
     * @param {Buffer} clientDataHash
     * @param {number} storedCounter
     * @returns {{isValid: boolean, newCounter: number}}
     */
    static verifyAssertion(publicKey, assertionRaw, clientDataHash, storedCounter = 0) {
        if (!assertionRaw || assertionRaw.length < 37) {
            return { isValid: false, newCounter: storedCounter };
        }
        try {
            const authData = assertionRaw.subarray(0, 37);
            const signature = assertionRaw.subarray(37);

            // Compteur incrémental monotone sur 4 octets big-endian (octets 33 à 37)
            const counter = authData.readUInt32BE(33);
            if (counter <= storedCounter) {
                return { isValid: false, newCounter: storedCounter };
            }

            const signedData = Buffer.concat([authData, clientDataHash]);
            const keyObj = typeof publicKey === 'string' || Buffer.isBuffer(publicKey)
                ? crypto.createPublicKey(publicKey)
                : publicKey;

            const isValid = crypto.verify('sha256', signedData, keyObj, signature);
            return { isValid, newCounter: isValid ? counter : storedCounter };
        } catch (e) {
            return { isValid: false, newCounter: storedCounter };
        }
    }
}

/**
 * Validateur pour Google Play Integrity (Titan M / TEE Keystore).
 */
export class PlayIntegrityValidator {
    /**
     * Décode et valide le jeton JWS émis par Google Play Integrity.
     * @param {string} token
     * @param {string|null} expectedPackageName
     * @param {string|null} expectedNonce
     * @param {number} maxAgeMs
     * @returns {{isValid: boolean, payload: object}}
     */
    static decodeAndVerifyJws(token, expectedPackageName = null, expectedNonce = null, maxAgeMs = 180000) {
        if (!token || typeof token !== 'string') return { isValid: false, payload: {} };
        const parts = token.trim().split('.');
        if (parts.length !== 3) return { isValid: false, payload: {} };

        try {
            const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
            const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
            const signature = base64UrlDecode(parts[2]);

            // 1. Vérification de la signature cryptographique du signataire Google via x5c
            if (Array.isArray(header.x5c) && header.x5c.length > 0) {
                const certDer = Buffer.from(header.x5c[0], 'base64');
                const cert = new crypto.X509Certificate(certDer);
                const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
                const derSignature = signature.length === 64 ? ieeeP1363ToDer(signature) : signature;
                const verified = crypto.verify('sha256', signingInput, cert.publicKey, derSignature);
                if (!verified) {
                    return { isValid: false, payload };
                }
            }

            // 2. Vérification de l'anti-rejeu (Nonce)
            const reqDetails = payload.requestDetails || {};
            if (expectedNonce && reqDetails.nonce !== expectedNonce) {
                return { isValid: false, payload };
            }

            // 3. Validation de l'horodatage
            if (reqDetails.timestampMillis) {
                const ts = Number(reqDetails.timestampMillis);
                if (Math.abs(Date.now() - ts) > maxAgeMs) {
                    return { isValid: false, payload };
                }
            }

            // 4. Vérification de l'application cliente
            if (expectedPackageName) {
                const appInteg = payload.appIntegrity || {};
                if (appInteg.packageName !== expectedPackageName) {
                    return { isValid: false, payload };
                }
            }

            // 5. Verdict d'intégrité matérielle
            const devInteg = payload.deviceIntegrity || {};
            const verdicts = devInteg.deviceRecognitionVerdict || [];
            const isHardwareStrong = verdicts.includes('MEETS_STRONG_INTEGRITY') || verdicts.includes('MEETS_DEVICE_INTEGRITY');

            return { isValid: isHardwareStrong, payload };
        } catch (e) {
            return { isValid: false, payload: {} };
        }
    }
}

/**
 * Gestionnaire du standard Device Bound Session Credentials (DBSC - W3C).
 */
export class DbscSessionManager {
    /**
     * Valide la preuve DBSC reçue dans l'en-tête HTTP Sec-Session-Response.
     * @param {string} dbscJwt
     * @param {object} jwkCléMatérielle
     * @param {string} expectedSessionId
     * @param {string} expectedOrigin
     * @param {string|null} expectedNonce
     * @returns {boolean}
     */
    static verifySessionProof(dbscJwt, jwk, expectedSessionId, expectedOrigin, expectedNonce = null) {
        if (!dbscJwt || typeof dbscJwt !== 'string' || !jwk) return false;
        const parts = dbscJwt.trim().split('.');
        if (parts.length !== 3) return false;

        try {
            const header = JSON.parse(base64UrlDecode(parts[0]).toString('utf8'));
            const payload = JSON.parse(base64UrlDecode(parts[1]).toString('utf8'));
            const rawSig = base64UrlDecode(parts[2]);

            if (header.typ !== 'dbsc+jwt' && header.typ !== 'jwt') return false;
            if (payload.sub !== expectedSessionId) return false;
            if (expectedOrigin && payload.aud && payload.aud !== expectedOrigin) return false;
            if (expectedNonce && payload.nonce !== expectedNonce) return false;
            if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return false;

            const keyObj = crypto.createPublicKey({ key: jwk, format: 'jwk' });
            const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
            const derSig = rawSig.length === 64 ? ieeeP1363ToDer(rawSig) : rawSig;

            return crypto.verify('sha256', signingInput, keyObj, derSig);
        } catch (e) {
            return false;
        }
    }
}

/**
 * Orchestrateur central de validation d'attestation matérielle.
 */
export class HardwareAttestationManager {
    constructor(store, config = {}) {
        this.store = store;
        this.config = config;
    }

    async process(context, sessionId, clientIp, origin) {
        const headers = context.headers || {};

        // 1. DBSC (W3C TPM 2.0 / Clé matérielle de session)
        const dbscHeader = headers['sec-session-response'];
        if (dbscHeader && sessionId) {
            const sessionRec = await this.store.get(`dbsc-session:${sessionId}`);
            if (sessionRec && sessionRec.jwk) {
                const nonce = await this.store.get(`dbsc-nonce:${sessionId}`);
                if (DbscSessionManager.verifySessionProof(dbscHeader, sessionRec.jwk, sessionId, origin, nonce)) {
                    await this.store.delete(`dbsc-nonce:${sessionId}`);
                    return { verified: true, type: 'dbsc_tpm', details: { sessionId } };
                }
            }
        }

        // 2. Google Play Integrity (Titan M / Android TEE)
        const playToken = headers['x-play-integrity-token'] || headers['x-play-integrity'];
        if (playToken) {
            const pkgName = this.config.androidPackageName || null;
            const nonce = await this.store.get(`play-integrity-nonce:${clientIp}`);
            const { isValid, payload } = PlayIntegrityValidator.decodeAndVerifyJws(playToken, pkgName, nonce);
            if (isValid) {
                if (nonce) await this.store.delete(`play-integrity-nonce:${clientIp}`);
                return { verified: true, type: 'google_play_integrity_strong', details: payload };
            }
        }

        // 3. Apple App Attest (Secure Enclave)
        const appleHeader = headers['x-apple-app-attest'];
        if (appleHeader) {
            try {
                const { keyId, assertion } = typeof appleHeader === 'string' ? JSON.parse(appleHeader) : appleHeader;
                const deviceData = await this.store.get(`app-attest:${keyId}`);
                if (deviceData && deviceData.publicKeyPem) {
                    const clientDataHash = crypto.createHash('sha256').update(`${sessionId}:${clientIp}`).digest();
                    const rawAssertion = Buffer.from(assertion, 'base64');
                    const { isValid, newCounter } = AppleAppAttestValidator.verifyAssertion(deviceData.publicKeyPem, rawAssertion, clientDataHash, deviceData.counter || 0);
                    if (isValid) {
                        deviceData.counter = newCounter;
                        await this.store.set(`app-attest:${keyId}`, deviceData, 86400 * 30);
                        return { verified: true, type: 'apple_secure_enclave', details: { keyId, counter: newCounter } };
                    }
                }
            } catch (e) {}
        }

        return { verified: false, type: 'none', details: {} };
    }
}