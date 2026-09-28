import {cyrb53} from "./fingerprint.builder.js";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

/**
 * Verifies a Zero-Knowledge Proof (ZKP) of the Schnorr type.
 * The verification checks that g^s ≡ t * y^c (mod p),
 * where c is a challenge computed by SHA-256 hashing of (g, y, t).
 *
 * @param {string} yStr - The public key y, hex-encoded (without the 0x prefix).
 * @param {string} tStr - The commitment t, hex-encoded (without the 0x prefix).
 * @param {string} sStr - The response s, hex-encoded (without the 0x prefix).
 * @returns {boolean} True if the proof is valid, false otherwise (or on error).
 */
export function verifyZkpProof(yStr, tStr, sStr) {
    try {
        const y = BigInt('0x' + yStr);
        const t = BigInt('0x' + tStr);
        const s = BigInt('0x' + sStr);

        const ZKP_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663n;
        const ZKP_G = 2n;

        const cStr = ZKP_G.toString() + y.toString() + t.toString();
        const hashHex = crypto.createHash('sha256').update(cStr).digest('hex');
        const c = BigInt('0x' + hashHex) % ZKP_P;

        return modPow(ZKP_G, s, ZKP_P) === (t * modPow(y, c, ZKP_P)) % ZKP_P;
    } catch (e) {
        return false;
    }
}

/**
 * Serializes a value to JSON while escaping dangerous characters
 * for safe inclusion in HTML/JS (XSS prevention).
 * Escapes <, >, U+2028, and U+2029.
 *
 * @param {*} val - The value to serialize.
 * @returns {string} The escaped JSON string.
 */
export function safeJsonStringify(val) {
    return JSON.stringify(val)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

/**
 * Sanitizes and validates a redirect path to prevent open redirects.
 * - Strips out disallowed characters.
 * - Prevents protocol-relative redirects (//evil.com).
 * - Prevents absolute redirects (http://evil.com).
 * - Ensures the path starts with a single '/'.
 *
 * @param {string} p - The raw redirect path.
 * @returns {string} The sanitized path (or '/' by default).
 */
export function sanitizeRedirectPath(p) {
    if (typeof p !== 'string') return '/';
    let sanitized = p.replace(/[^a-zA-Z0-9\/.\-_~%?&=:@+,;]/g, '');

    // Prevent protocol-relative redirects (e.g. //evil.com)
    if (sanitized.startsWith('//')) {
        sanitized = '/' + sanitized.replace(/^\/+/g, '');
    }
    // Prevent absolute redirects (e.g. http://evil.com)
    if (/^https?:\/\//i.test(sanitized)) {
        try {
            const parsed = new URL(sanitized);
            sanitized = parsed.pathname + parsed.search + parsed.hash;
        } catch (e) {
            sanitized = '/';
        }
    }
    if (!sanitized.startsWith('/')) {
        sanitized = '/' + sanitized;
    }
    return sanitized.replace(/^\/+/g, '/');
}

/**
 * Decodes a polymorphic fingerprint by restoring the original keys
 * from a mapping of randomized keys.
 * Expected format: "randKey: value|randKey: value|...".
 *
 * @param {string} fpString - The encoded fingerprint.
 * @param {object} mapping - The mapping object containing `keys` (orig -> rand).
 * @returns {string} The decoded fingerprint with original keys.
 */
export function decodePolymorphicFingerprint(fpString, mapping) {
    if (!fpString || !mapping || !mapping.keys) return fpString;
    const reverseKeys = {};
    for (const [orig, rand] of Object.entries(mapping.keys)) {
        reverseKeys[rand] = orig;
    }
    const parts = fpString.split('|');
    const mappedParts = parts.map(part => {
        const pair = part.split(':');
        if (pair.length === 2) {
            const origKey = reverseKeys[pair[0]] || pair[0];
            return `${origKey}:${pair[1]}`;
        }
        return part;
    });
    return mappedParts.join('|');
}

/**
 * Extracts and parses a Private Access Token (PAT / Privacy Pass / RFC 9578).
 * Supports 'Authorization: PrivateToken token="..."' and 'Sec-Private-State-Token'.
 *
 * @param {object} headers - HTTP request headers object.
 * @returns {Array<Uint8Array>} Array of raw binary tokens.
 */
export function extractPrivateAccessTokens(headers) {
    if (!headers) return [];
    const tokens = [];

    const authHeader = headers['authorization'] || headers['Authorization'];
    if (typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('privatetoken ')) {
        const match = authHeader.match(/token=(?:"([^"]+)"|([a-zA-Z0-9_\-+/=]+))/i);
        if (match) {
            const rawB64 = match[1] || match[2];
            try {
                tokens.push(Buffer.from(rawB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
            } catch (e) {}
        }
    }

    const pstHeader = headers['sec-private-state-token'] || headers['Sec-Private-State-Token'];
    if (typeof pstHeader === 'string') {
        const parts = pstHeader.split(',');
        for (const part of parts) {
            const trimmed = part.trim();
            if (trimmed) {
                try {
                    tokens.push(Buffer.from(trimmed.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
                } catch (e) {}
            }
        }
    }

    return tokens;
}

/**
 * Decodes an RFC 9578 Token structure:
 * uint16_t token_type (2 bytes)
 * uint8_t nonce[32] (32 bytes)
 * uint8_t challenge_digest[32] (32 bytes)
 * uint8_t token_key_id[32] (32 bytes)
 * uint8_t authenticator[Nk] (>= 32 bytes)
 *
 * @param {Uint8Array|Buffer} buffer
 * @returns {object|null}
 */
export function parsePrivateAccessToken(buffer) {
    if (!buffer || buffer.length < 98) return null; // 2 + 32 + 32 + 32 = 98 min

    const view = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
    const tokenType = view.readUInt16BE(0);
    const nonce = view.subarray(2, 34);
    const challengeDigest = view.subarray(34, 66);
    const tokenKeyId = view.subarray(66, 98);
    const authenticator = view.subarray(98);

    if (authenticator.length === 0) return null;

    return {
        tokenType,
        nonce: nonce.toString('hex'),
        challengeDigest: challengeDigest.toString('hex'),
        tokenKeyId: tokenKeyId.toString('hex'),
        authenticator,
        signedData: view.subarray(0, 98)
    };
}

/**
 * Validates a decoded Private Access Token signature against configured public keys.
 *
 * @param {object} parsedToken - Output from parsePrivateAccessToken.
 * @param {object} patConfig - Configuration with trustedKeys mapping.
 * @returns {boolean} True if signature is cryptographically valid.
 */
export function verifyPatSignature(parsedToken, patConfig = {}) {
    if (!parsedToken) return false;
    const trustedKeys = patConfig.trustedKeys || {};
    const keyId = parsedToken.tokenKeyId;
    const publicKey = trustedKeys[keyId] || trustedKeys[keyId.toLowerCase()] || patConfig.defaultPublicKey;

    if (!publicKey) {
        return false;
    }

    const { tokenType, signedData, authenticator } = parsedToken;

    try {
        // Type 0x0001 (Blind RSA 2048) / 0x0002 (Rate-Limited Blind RSA)
        if (tokenType === 0x0001 || tokenType === 0x0002 || tokenType === 1 || tokenType === 2) {
            // Try RSA-PSS with SHA-384 (RFC 9577) first, fallback to SHA-256 and PKCS#1 v1.5
            const algorithms = [
                { hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 },
                { hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
                { hash: 'sha384', padding: crypto.constants.RSA_PKCS1_PADDING },
                { hash: 'sha256', padding: crypto.constants.RSA_PKCS1_PADDING }
            ];

            for (const alg of algorithms) {
                try {
                    const verifier = crypto.createVerify(alg.hash);
                    verifier.update(signedData);
                    const isValid = verifier.verify({
                        key: publicKey,
                        padding: alg.padding,
                        saltLength: alg.saltLength
                    }, authenticator);
                    if (isValid) return true;
                } catch (verifyErr) {}
            }
        } else if (tokenType === 0x0003 || tokenType === 3) {
            // VOPRF / Ed25519 authentication verification
            try {
                return crypto.verify(null, signedData, publicKey, authenticator);
            } catch (voprfErr) {}
        }
    } catch (e) {
        return false;
    }
    return false;
}

/**
 * @private
 * Deep merges two objects. The `source` object's properties overwrite the `target`'s.
 * @param {object} target - The target object.
 * @param {object} source - The source object.
 * @returns {object} The merged object.
 */
export function deepMerge(target, source) {
    const output = { ...target };
    if (target && typeof target === 'object' && source && typeof source === 'object') {
        Object.keys(source).forEach(key => {
            if (source[key] && typeof source[key] === 'object' && key in target) {
                output[key] = deepMerge(target[key], source[key]);
            } else {
                output[key] = source[key];
            }
        });
    }
    return output;
}

/**
 * Creates a stable hash based on device characteristics, independent of the IP.
 * This is our "level 2 fingerprint".
 * @param {object} context - The request context.
 * @returns {string} A hash representing the device.
 */
export function getHeaderSignature(context) {
    if (!context.rawHeaders) return '';
    const headerKeys = [];
    for (let i = 0; i < context.rawHeaders.length; i += 2) {
        headerKeys.push(context.rawHeaders[i]);
    }
    return cyrb53(headerKeys.sort().join(','));
}

/**
 * Analyses a raw JA3 string.
 * Format: "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats"
 * @param {string} ja3String
 * @returns {object|null}
 */
export function parseJa3(ja3String) {
    if (!ja3String || typeof ja3String !== 'string') {
        return null;
    }
    const parts = ja3String.split(',');
    if (parts.length !== 5) {
        return null;
    }
    return {
        tlsVersion: parseInt(parts[0], 10),
        ciphers: parts[1] !== '' ? parts[1].split('-').map(Number) : [],
        extensions: parts[2] !== '' ? parts[2].split('-').map(Number) : [],
        curves: parts[3] !== '' ? parts[3].split('-').map(Number) : [],
        points: parts[4] !== '' ? parts[4].split('-').map(Number) : []
    };
}

/**
 * Computes modular exponentiation (base^exponent mod modulus) efficiently
 * using the binary exponentiation method (square-and-multiply).
 *
 * @param {bigint} base - The base.
 * @param {bigint} exponent - The exponent.
 * @param {bigint} modulus - The modulus.
 * @returns {bigint} The result of base^exponent mod modulus.
 */
export function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) {
            result = (result * base) % modulus;
        }
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
}


/**
 * Computes a simple hash of the IP network by applying a mask (CIDR prefix).
 * For example, with a prefix of 24, only the first 3 octets are kept.
 *
 * @param {string} ip - The IP address in IPv4 format (e.g. "192.168.1.42").
 * @param {number} [prefix=24] - The network prefix length (in bits).
 * @returns {string|null} A hexadecimal hash of the network, or null if the IP is invalid.
 */
export function hashNetwork(ip, prefix = 24) {
    // Network hash (/24 or /16 mask)
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    const maskBytes = prefix / 8;
    const network = parts.slice(0, maskBytes).join('.');
    // Basic hash
    let hash = 0;
    for (let i = 0; i < network.length; i++) {
        const char = network.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString(16);
}

/**
 * Checks whether an IP address is a loopback address (localhost).
 * Handles IPv4, IPv6, and the IPv4-mapped prefix (::ffff:).
 *
 * @param {string} ip - The IP address to test.
 * @returns {boolean} True if the IP is a loopback address, false otherwise.
 */
export function isLoopbackIp(ip) {
    if (!ip || typeof ip !== 'string') return true;
    let cleanIp = ip.trim().toLowerCase();
    if (cleanIp.startsWith('::ffff:')) {
        cleanIp = cleanIp.substring(7);
    }
    return cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost' ||
        cleanIp.startsWith('127.') || cleanIp === '0.0.0.0' || cleanIp === '::';
}

/**
 * Normalizes a referer URL by keeping only the protocol and hostname
 * (e.g. "https://example.com").
 *
 * @param {string} referer - The raw referer URL.
 * @returns {string} The normalized URL, or the original value if invalid.
 */
export function normalizeReferer(referer) {
    try {
        const url = new URL(referer);
        return `${url.protocol}//${url.hostname}`;
    } catch {
        return referer;
    }
}

/**
 * Checks whether an IP address belongs to a private range (RFC 1918, loopback,
 * link-local, CGNAT, etc.). Handles both IPv4 and IPv6 formats.
 *
 * @param {string} ip - The IP address to test.
 * @returns {boolean} True if the IP is private, false otherwise.
 */
export function isPrivateIp(ip) {
    if (!ip || typeof ip !== 'string') return false;
    let cleanIp = ip.trim().toLowerCase();
    if (cleanIp.startsWith('::ffff:')) {
        cleanIp = cleanIp.substring(7);
    }
    if (cleanIp === '127.0.0.1' || cleanIp === '::1' || cleanIp === 'localhost' || cleanIp.startsWith('127.')) {
        return true;
    }
    const parts = cleanIp.split('.');
    if (parts.length === 4) {
        const first = parseInt(parts[0], 10);
        const second = parseInt(parts[1], 10);
        if (first === 127 || first === 10 || first === 0) return true;
        if (first === 172 && second >= 16 && second <= 31) return true;
        if (first === 192 && second === 168) return true;
        if (first === 169 && second === 254) return true;
        if (first === 100 && second >= 64 && second <= 127) return true;
    }
    if (cleanIp.startsWith('fc') || cleanIp.startsWith('fd') || cleanIp.startsWith('fe80:')) {
        return true;
    }
    return false;
}

/**
 * Basic User-Agent parsing to extract:
 * - the browser (with major version),
 * - the operating system,
 * - the device type (mobile, tablet, desktop).
 *
 * @param {string} ua - The User-Agent string.
 * @returns {object} An object { browser?, os?, device }.
 */
export function parseUserAgent(ua) {
    // Basic User-Agent parser
    const result = {};

    // Browser detection
    if (ua.includes('Chrome') && !ua.includes('Edg')) {
        result.browser = 'Chrome';
        const match = ua.match(/Chrome\/(\d+)/);
        if (match) result.browser += `/${match[1]}`;
    } else if (ua.includes('Firefox')) {
        result.browser = 'Firefox';
        const match = ua.match(/Firefox\/(\d+)/);
        if (match) result.browser += `/${match[1]}`;
    } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
        result.browser = 'Safari';
        const match = ua.match(/Version\/(\d+)/);
        if (match) result.browser += `/${match[1]}`;
    } else if (ua.includes('Edg')) {
        result.browser = 'Edge';
        const match = ua.match(/Edg\/(\d+)/);
        if (match) result.browser += `/${match[1]}`;
    }

    // OS detection
    if (ua.includes('Windows NT 10.0')) result.os = 'Windows 10';
    else if (ua.includes('Windows NT 6.1')) result.os = 'Windows 7';
    else if (ua.includes('Mac OS X')) result.os = 'macOS';
    else if (ua.includes('Linux') && !ua.includes('Android')) result.os = 'Linux';
    else if (ua.includes('Android')) result.os = 'Android';
    else if (ua.includes('iPhone') || ua.includes('iPad')) result.os = 'iOS';

    // Device form-factor detection
    if (ua.includes('Mobile')) result.device = 'mobile';
    else if (ua.includes('Tablet')) result.device = 'tablet';
    else result.device = 'desktop';

    return result;
}

/**
 * Programmatically generates an Ed25519 key pair in PEM format
 * (PKCS#8 for private key, SPKI for public key) matching OpenSSL CLI:
 * `openssl genpkey -algorithm ed25519 -out issuer-private.pem`
 * `openssl pkey -in issuer-private.pem -pubout -out issuer-public.pem`
 *
 * @param {string} [outDir='./config'] Target directory to store the PEM files.
 * @param {object} [options={}] Optional configuration (e.g. custom file names).
 * @returns {{privateKeyPath: string, publicKeyPath: string, privateKey: string, publicKey: string}}
 */
export function generateIssuerPemKeys(outDir = './config', options = {}) {
    const privateKeyName = options.privateKeyName || 'issuer-private.pem';
    const publicKeyName = options.publicKeyName || 'issuer-public.pem';

    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' }
    });

    if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
    }

    const privateKeyPath = path.join(outDir, privateKeyName);
    const publicKeyPath = path.join(outDir, publicKeyName);

    fs.writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    fs.writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

    return {
        privateKeyPath,
        publicKeyPath,
        privateKey,
        publicKey
    };
}