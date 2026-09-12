import {cyrb53} from "./fingerprint.builder.js";

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

export function safeJsonStringify(val) {
    return JSON.stringify(val)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

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


export function hashNetwork(ip, prefix = 24) {
    // Hash du réseau (masque /24 ou /16)
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    const maskBytes = prefix / 8;
    const network = parts.slice(0, maskBytes).join('.');
    // Hash simple
    let hash = 0;
    for (let i = 0; i < network.length; i++) {
        const char = network.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return hash.toString(16);
}
export function normalizeReferer(referer) {
    try {
        const url = new URL(referer);
        return `${url.protocol}//${url.hostname}`;
    } catch {
        return referer;
    }
}

export function isPrivateIp(ip) {
    // Vérifier si l'IP est privée
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const first = parseInt(parts[0]);
    return (first === 10) || (first === 172 && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) || (first === 192 && parseInt(parts[1]) === 168);
}
// Fonctions utilitaires
export function parseUserAgent(ua) {
    // Parser basique du User-Agent
    const result = {};

    // Détection du navigateur
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

    // Détection de l'OS
    if (ua.includes('Windows NT 10.0')) result.os = 'Windows 10';
    else if (ua.includes('Windows NT 6.1')) result.os = 'Windows 7';
    else if (ua.includes('Mac OS X')) result.os = 'macOS';
    else if (ua.includes('Linux') && !ua.includes('Android')) result.os = 'Linux';
    else if (ua.includes('Android')) result.os = 'Android';
    else if (ua.includes('iPhone') || ua.includes('iPad')) result.os = 'iOS';

    // Détection du type d'appareil
    if (ua.includes('Mobile')) result.device = 'mobile';
    else if (ua.includes('Tablet')) result.device = 'tablet';
    else result.device = 'desktop';

    return result;
}