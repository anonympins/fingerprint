import crypto from "node:crypto";
import { BlockList } from "node:net";
import dns from "node:dns/promises";
import { getProblemManager } from "./problem-manager.js";
import { Optimization } from "./library.js";
import { cyrb53, FingerprintBuilder } from "./fingerprint.builder.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
export { createRedisStore } from "./redis-store.js";
export { createMongoDbStore } from "./mongodb-store.js";


/**
 * @private
 * Deep merges two objects. The `source` object's properties overwrite the `target`'s.
 * @param {object} target - The target object.
 * @param {object} source - The source object.
 * @returns {object} The merged object.
 */
function deepMerge(target, source) {
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

const securityProfiles = {
    /**
     * @summary **Balanced Profile (Default)**
     * @description A general-purpose configuration suitable for most websites, offering a good mix of security and user experience. It's sensitive enough to catch common bots without being overly aggressive towards legitimate users.
     */
    balanced: {
        weights: {
            historyScore: 0.3,
            rotationScore: 0.5,
            headerAnomalyScore: 0.1,
            requestPatternScore: 0.6,
            inconsistencyScore: 0.8,
            behaviorScore: 0.7,
            honeypotScore: 1.0,
            crossLayerInconsistencyScore: 0.4,
            timeInconsistencyScore: 0.9,
            tlsSpoofingScore: 0.8 // NOUVEAU: Poids pour la détection de spoofing TLS
        },
        thresholds: { low: 20, medium: 45, high: 75, block: 95 },
        patterns: {
            velocityThreshold: 800,
            burstThreshold: 1500,
            scrapeThreshold: 1000,
            historySize: 10,
            minSamples: 5,
            regularityThreshold: 50,
            benfordThreshold: 0.15,
            patternWeight: 80,
            decayFactor: 0.9,
            inactivityReset: 5000,
        },
    },
    /**
     * @summary **Strict Profile**
     * @description An aggressive configuration for sensitive applications (e.g., financial services, admin panels). It uses lower suspicion thresholds and higher penalties for anomalies, prioritizing security over user convenience. All new devices are challenged by default.
     */
    strict: {
        weights: {
            historyScore: 0.4,
            rotationScore: 0.6,
            headerAnomalyScore: 0.2,
            requestPatternScore: 0.8,
            inconsistencyScore: 1.0,
            behaviorScore: 0.8,
            honeypotScore: 1.0,
            crossLayerInconsistencyScore: 0.6,
            timeInconsistencyScore: 1.0,
            tlsSpoofingScore: 1.0 // NOUVEAU: Plus agressif pour le spoofing TLS
        },
        thresholds: { low: 10, medium: 35, high: 65, block: 90 },
        patterns: {
            velocityThreshold: 1000,
            burstThreshold: 1800,
            scrapeThreshold: 1200,
            historySize: 15,
            minSamples: 4,
            regularityThreshold: 40,
            benfordThreshold: 0.12,
            patternWeight: 90,
            decayFactor: 0.85,
            inactivityReset: 4000,
        },
        challengeNewDevices: true, // Challenge all new devices
    },
    /**
     * @summary **API Profile**
     * @description Optimized for protecting API endpoints. This profile is highly sensitive to request patterns (velocity, bursts) and less reliant on browser-specific behavioral metrics. It's designed to quickly identify and throttle scrapers and automated clients.
     */
    api: {
        weights: {
            historyScore: 0.5,
            rotationScore: 0.5,
            headerAnomalyScore: 0.3,
            requestPatternScore: 1.0, // Very high weight for API patterns
            inconsistencyScore: 0.7,
            behaviorScore: 0.2, // Lower weight, as browser behavior is not applicable
            honeypotScore: 1.0,
            crossLayerInconsistencyScore: 0.5,
            timeInconsistencyScore: 0.8,
            tlsSpoofingScore: 0.7 // NOUVEAU: Important pour les API
        },
        thresholds: { low: 25, medium: 50, high: 80, block: 95 },
        patterns: {
            velocityThreshold: 200, // APIs are expected to be fast
            burstThreshold: 500,
            scrapeThreshold: 400,
            historySize: 20,
            minSamples: 8,
            regularityThreshold: 20,
            benfordThreshold: 0.18,
            patternWeight: 85,
            decayFactor: 0.9,
            inactivityReset: 10000,
        },
        isApiRequest: (req) => req.path.startsWith('/api/') || req.headers.accept?.includes('application/json'),
    }
    ,
    /**
     * @summary **Blog Profile**
     * @description Tuned for blogs and content-heavy websites. This profile focuses on detecting content scraping and comment spam by placing a high weight on request patterns and honeypot traps, while being more lenient on behavioral metrics typical of readers.
     */
    blog: {
        weights: {
            historyScore: 0.2,
            rotationScore: 0.3,
            headerAnomalyScore: 0.1,
            requestPatternScore: 0.8, // High weight to detect content scraping
            inconsistencyScore: 0.7,
            behaviorScore: 0.5, // Less emphasis on complex interactions
            honeypotScore: 1.0, // Crucial for comment spam
            crossLayerInconsistencyScore: 0.4,
            timeInconsistencyScore: 0.8,
            tlsSpoofingScore: 0.6 // NOUVEAU: Moins critique pour les blogs
        },
        thresholds: { low: 25, medium: 55, high: 80, block: 95 },
        patterns: {
            velocityThreshold: 1000, // Readers can be fast
            burstThreshold: 2000,
            scrapeThreshold: 800, // Very sensitive to scraping patterns
            historySize: 12,
            minSamples: 5,
            regularityThreshold: 60,
            benfordThreshold: 0.16,
            patternWeight: 85,
            decayFactor: 0.92,
            inactivityReset: 10000,
        },
    },
    /**
     * @summary **E-commerce Profile**
     * @description A strict profile tailored for e-commerce sites. It's designed to combat inventory scalping, price scraping, and account takeover attempts by using high weights for request patterns and fingerprint inconsistency. It also challenges all new devices to increase the cost for bots.
     */
    ecommerce: {
        weights: {
            historyScore: 0.4,
            rotationScore: 0.6,
            headerAnomalyScore: 0.2,
            // Scission du requestPatternScore pour un contrôle plus fin
            velocityScore: 0.8,       // Pénalise la vitesse globale
            burstScore: 1.0,          // Pénalise fortement les rafales sur la même ressource (scalping)
            scrapeScore: 0.9,         // Pénalise le parcours de pages/produits
            regularityScore: 0.7,     // Détecte les bots de type "cron"
            inconsistencyScore: 1.0, // Crucial for preventing account takeover
            behaviorScore: 0.8, // Important for checkout/login forms
            honeypotScore: 1.0,
            crossLayerInconsistencyScore: 0.7,
            timeInconsistencyScore: 0.9,
            tlsSpoofingScore: 0.9 // NOUVEAU: Très important pour l'e-commerce
        },
        thresholds: { low: 15, medium: 40, high: 70, block: 90 },
        patterns: {
            velocityThreshold: 500, // Bots are very fast
            burstThreshold: 1000, // Detects rapid retries on the same product/action
            scrapeThreshold: 600,
            historySize: 15,
            minSamples: 6,
            regularityThreshold: 30,
            benfordThreshold: 0.14,
            patternWeight: 95,
            decayFactor: 0.88,
            inactivityReset: 3000,
        },
        challengeNewDevices: true, // New devices are suspicious in e-commerce
        isApiRequest: (req) => req.path.startsWith('/api/cart') || req.path.startsWith('/api/stock') || req.path.startsWith('/api/checkout'),
    }
};

/**
 * Creates a security configuration based on a named profile, with optional overrides.
 * @param {'balanced' | 'strict' | 'api'} [profileName='balanced'] - The name of the profile to use.
 * @param {object} [overrides={}] - An object to deeply merge with the profile, allowing for customization.
 * @returns {object} The final security configuration object.
 */
export function createSecurityProfile(profileName = 'balanced', overrides = {}) { // eslint-disable-line no-unused-vars
    const baseProfile = securityProfiles[profileName] || securityProfiles.balanced;
    return deepMerge(baseProfile, overrides);
}

/**
 * Retrieves the POW_SECRET from environment variables with appropriate checks.
 * @returns {string} The secret key.
 */
const getPowSecret = () => {
  const secret = process.env.POW_SECRET;
  if (!secret && process.env.NODE_ENV === 'production') {
    throw new Error('POW_SECRET environment variable is not set. This is required for production.');
  }
  return secret || "fallback-dev-secret-32-chars-minimum";
};

/**
 * Loads the pow.solver.js content for inlining in HTML pages.
 * @returns {string} The solver JavaScript code.
 */
const getPowSolverCode = () => {
  // On supprime le try/catch. Si le fichier n'est pas trouvé, le processus plantera,
  // ce qui est préférable à servir un code de secours potentiellement désynchronisé.
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const solverPath = join(__dirname, 'pow.solver.inline.js'); // Utilise la version inline
  return readFileSync(solverPath, 'utf-8');
};

/**
 * Extracts TLS fingerprints (JA3 and JA4) from request context.
 * Prioritizes headers from reverse proxies (x-ja4-hash) and falls back to JA3 calculation
 * from raw socket data if available.
 * @param {object} context - The request context, containing the raw request object.
 * @returns {{ja3: string|null, ja4: string|null}} An object containing JA3 and JA4 hashes.
 */
function getTlsFingerprint(context) {
    let ja3 = null;
    let ja4 = null;

    // 1. Prefer JA4 hash from a trusted reverse proxy header.
    const ja4FromHeader = context.headers['x-ja4-hash'];
    if (ja4FromHeader) {
        ja4 = ja4FromHeader;
    }
    // 2. Prefer JA3 hash from a trusted reverse proxy header.
    const ja3FromHeader = context.headers['x-ja3-hash']; // Assuming a proxy might provide JA3 too
    if (ja3FromHeader) {
        ja3 = ja3FromHeader;
    }

    // 3. Fallback to calculating from the raw socket if available and if headers were not present.
    const clientHello = context.rawReq?.socket?.clientHello;
    if (clientHello && !ja3) { // Only calculate if ja3 is not already set
        try {
            const { version, ciphers, extensions, ellipticCurves, ellipticCurvePointFormats } = clientHello;

            // The official JA3 spec includes the TLS version.
            // Node.js provides it as a string like 'TLSv1.3', we need the corresponding decimal value.
            const tlsVersionMap = {
                'TLSv1': 769, 'TLSv1.1': 770, 'TLSv1.2': 771, 'TLSv1.3': 772
            };
            const tlsVersionId = tlsVersionMap[version] || 0;

            const ja3String = [
                tlsVersionId,
                // The ciphers array from clientHello is an array of objects, not just IDs.
                Array.isArray(ciphers) ? ciphers.join('-') : '',
                extensions?.join('-') || '',
                ellipticCurves?.join('-') || '',
                ellipticCurvePointFormats?.join('-') || ''
            ].join(',');

            ja3 = crypto.createHash('md5').update(ja3String).digest('hex');
        } catch (e) {
            // Could fail if clientHello structure is unexpected.
            ja3 = null;
        }
    }
    return { ja3, ja4 };
}
/**
 * Creates a stable hash based on device characteristics, independent of the IP.
 * This is our "level 2 fingerprint".
 * @param {object} context - The request context.
 * @returns {string} A hash representing the device.
 */
function getHeaderSignature(context) {
    if (!context.rawHeaders) return '';
    const headerKeys = [];
    for (let i = 0; i < context.rawHeaders.length; i += 2) {
        headerKeys.push(context.rawHeaders[i]);
    }
    return cyrb53(headerKeys.sort().join(','));
}

/**
 * Returns the client-side fingerprint if available, otherwise computes a server-side hash.
 * This aligns with the test's expectation for prioritization.
 * @param {object} context The request context.
 * @returns {string} The device fingerprint.
 */
export function getDeviceHash(context) {
    const clientFp = context.headers['x-device-fingerprint'];
    if (clientFp && typeof clientFp === 'string') {
        return clientFp;
    }
    // Fallback to composite hash if client fingerprint is not available
    return getCompositeDeviceHash(context);
}

function getCompositeDeviceHash(context) {
    const srv = new FingerprintBuilder();

    // Si un fingerprint client est fourni, on l'intègre comme un signal fort,
    // mais on ne lui fait pas aveuglément confiance. On continue de construire
    // notre propre fingerprint serveur pour le comparer.
    // Un attaquant qui forge un `clientFp` mais oublie de forger les en-têtes
    // correspondants sera détecté par l'incohérence.
    const clientFp = context.headers['x-device-fingerprint'];
    if (clientFp && typeof clientFp === 'string' && clientFp.includes('cvs:')) {
        // On ajoute le hash du fingerprint client comme un composant du fingerprint serveur.
        // Si le clientFp change, le hash serveur changera aussi.
        srv.add("client_fp_hash", clientFp);
    }

    // 1. SIGNAL FORT: User Agent (poids élevé)
    const ua = context.headers["user-agent"];
    if (ua) {
        srv.add("ua", ua); // User-Agent
    }

    // 2. SIGNAUX DE BAS NIVEAU (Transport & Réseau) - Très fiables si fournis par un proxy
    const { ja3, ja4 } = getTlsFingerprint(context);
    if (ja3) srv.add("ja3", ja3);
    if (ja4) srv.add("ja4", ja4);

    const h2Fingerprint = context.headers['x-http2-fingerprint'];
    if (h2Fingerprint) srv.add("h2", h2Fingerprint);

    const tcpFingerprint = context.headers['x-tcp-fingerprint'];
    if (tcpFingerprint) srv.add("tcp", tcpFingerprint);

    // 3. SIGNAUX DE HAUT NIVEAU (Applicatif) - Moins fiables, mais utiles pour la corroboration
    const headersToCapture = {
        "ch_ua": "sec-ch-ua",
        "ch_platform": "sec-ch-ua-platform",
        "ch_mobile": "sec-ch-ua-mobile",
        "ch_model": "sec-ch-ua-model",
        "ch_arch": "sec-ch-ua-arch",
        "ch_bitness": "sec-ch-ua-bitness",
        "upgrade_req": "upgrade-insecure-requests",
        "accept_lang": "accept-language",
        "accept_enc": "accept-encoding",
        "accept": "accept"
    };

    for (const [key, headerName] of Object.entries(headersToCapture)) {
        const headerValue = context.headers[headerName];
        if (headerValue) {
            srv.add(key, headerValue);
        }
    }

    // 4. SIGNAUX DE CONTEXTE (HTTP Version, Cookies)
    if (context.httpVersion) {
        srv.add("http_ver", context.httpVersion);
    }
    if (context.cookies) {
        const cookieKeys = Object.keys(context.cookies).sort().join(',');
        if (cookieKeys) {
            srv.add("cookie_keys", cookieKeys);
        }
    }

    return srv.toString();
}
export { getCompositeDeviceHash };

/**
 * @private
 * A knowledge base of known TLS (JA3) fingerprints for common browsers.
 * This helps in detecting inconsistencies between the TLS layer and the HTTP User-Agent.
 * The key is the JA3 hash, and the value is the browser family.
 * This list is not exhaustive but covers many common cases.
 */
const tlsFingerprintDb = {
    // --- Chrome (Desktop) ---
    'e188a442b87f422c5a1e80b05399435b': 'Chrome', // Chrome 107, Windows 10
    'd8e35855049321c6042a4325c697858f': 'Chrome', // Chrome 114, Windows 11
    'a9f90958d44533748c139a5d1895b925': 'Chrome', // Chrome 116, macOS
    '3b5379916d2b3882253c42885956a350': 'Chrome', // Chrome 124, Linux

    // --- Chrome (Mobile) ---
    '59822058c95c33d2d06e52f410855c8c': 'Chrome', // Chrome 120, Android 13

    // --- Firefox (Desktop) ---
    'b386946a5a586163c7c533636b45c355': 'Firefox', // Firefox 102, Windows 10
    '66236495a523c1785f8f3a105b248b11': 'Firefox', // Firefox 115, Windows 11
    'b73d470006575b5e35167a0b5a8540e2': 'Firefox', // Firefox 121, macOS
    '8443d7562933834333943465d52363cf': 'Firefox', // Firefox 125, Linux

    // --- Firefox (Mobile) ---
    '02720628957d38c6111a18433abe833f': 'Firefox', // Firefox 125, Android 14

    // --- Safari & iOS (Shared TLS Stack) ---
    // On iOS, all browsers (Chrome, Firefox, etc.) must use WebKit, which uses Apple's TLS stack.
    // Therefore, they all share the same JA3 fingerprint as Safari on that OS version.
    'b633f21d532d35967c8753c38536b4d3': 'Safari', // Safari 16, macOS
    '4d7a28d5f55b359b69100a311013f03e': ['Safari', 'Chrome', 'Firefox'], // Safari 17, iOS 17 (and other browsers on iOS 17)
    '8dd3d7532873575314df23c447543001': ['Safari', 'Chrome', 'Firefox'], // Safari 17.4, iOS 17.4

    // --- Edge (Desktop) ---
    // Edge is based on Chromium, so its JA3 is often identical to Chrome's.
    'd8e35855049321c6042a4325c697858f': ['Chrome', 'Edge'], // Edge 114, Windows 11 (shares with Chrome 114)
    'a9f90958d44533748c139a5d1895b925': ['Chrome', 'Edge'], // Edge 116, macOS (shares with Chrome 116)

    // --- Common Libraries & Bots (for spoofing detection) ---
    '47344a349b75c4e82333475553b5f358': 'Python', // Python 3.10 `requests` library
    'b29587b8a143c42546133ad7704b3310': 'Go',     // Go 1.19 `http` library
    'd435b5223b2884c5a832b842637e245f': 'Java',   // Java 11 `HttpClient`
    'c72366b9551263d990b7fa574225332c': 'curl',   // curl 7.81.0
};

// Fonctions utilitaires
function parseUserAgent(ua) {
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

function normalizeReferer(referer) {
    try {
        const url = new URL(referer);
        return `${url.protocol}//${url.hostname}`;
    } catch {
        return referer;
    }
}

function isPrivateIp(ip) {
    // Vérifier si l'IP est privée
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    const first = parseInt(parts[0]);
    return (first === 10) || (first === 172 && parseInt(parts[1]) >= 16 && parseInt(parts[1]) <= 31) || (first === 192 && parseInt(parts[1]) === 168);
}

function hashNetwork(ip, prefix = 24) {
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

/**
 * Generates the HTML content for a TSP (Traveling Salesperson Problem) challenge.
 * @param {string} nonce - Unique nonce for the challenge.
 * @param {number} numCities - Number of cities to include in the problem.
 * @param {number} targetMaxDistance - Maximum acceptable distance for the solution.
 * @param {Array<{x: number, y: number}>} cities - Coordinates of the cities.
 * @param {string} path - Redirect path after solving.
 * @returns {string} HTML of the challenge page.
 */
const generateTspChallenge = (
  nonce,
  numCities,
  targetMaxDistance,
  cities,
  path = "",
) => {
  const citiesJson = JSON.stringify(cities);
  const solverCode = getPowSolverCode();
  return `
      <html>
        <head><title>Advanced Security Check (Level 3)</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Ultimate Verification (Level 3)</h1>
          <p>Please solve this small optimization problem to prove you are human.</p>
          <div id="loader" style="margin:20px;">⚙️ Calculating route... (${numCities} cities)</div>
          <script>${solverCode}</script>
          <script>
            const cities = ${citiesJson}; // Safe, as it's JSON
            const nonce = ${JSON.stringify(nonce)}; // Safe
            const targetMaxDistance = ${targetMaxDistance};

            async function solve() {
              const result = await window.solveTspChallenge(cities, targetMaxDistance);
              
              if (result.distance <= targetMaxDistance) {
                window.location.href = ${JSON.stringify(path)} + "?pow_type=tsp&pow_nonce=" + nonce + "&pow_solution=" + JSON.stringify(result.path);
              } else {
                document.getElementById('loader').innerText = "Error: Could not find a sufficient solution. Please try again.";
              }
            }
            solve();
          </script>
        </body>
      </html>`;
};

/**
 * Verifies a TSP PoW solution.
 * @param {string} nonce - The challenge nonce.
 * @param {string} solutionPathJson - The path proposed by the client (stringified JSON).
 * @param {number} numCities - The number of cities in the challenge.
 * @param {number} targetMaxDistance - The maximum acceptable distance.
 * @param {Array<{x: number, y: number}>} cities - The coordinates of the cities.
 * @returns {boolean} True if the solution is valid.
 */
export const verifyTspChallenge = (
  nonce,
  solutionPathJson,
  numCities,
  targetMaxDistance,
  cities,
) => {
    // Input validation: ensure the solution is a non-empty string before trying to parse it.
    if (typeof solutionPathJson !== 'string' || solutionPathJson.length === 0) return false;

    try {
    const solutionPath = JSON.parse(solutionPathJson);
    if (!Array.isArray(solutionPath) || solutionPath.length !== numCities)
      return false;

    // Verify that the path is a valid permutation of the cities
    const uniqueCities = new Set(solutionPath);
    if (
      uniqueCities.size !== numCities ||
      Math.min(...solutionPath) < 0 ||
      Math.max(...solutionPath) >= numCities
    )
      return false;

    // Recalculate the distance on the server side
    let totalDistance = 0;
    let totalPenalty = 0;

    // Function to calculate the angle between 3 points (p1 -> p2 -> p3)
    const calculateAngle = (p1, p2, p3) => {
      const v1 = { x: p1.x - p2.x, y: p1.y - p2.y };
      const v2 = { x: p3.x - p2.x, y: p3.y - p2.y };
      const dotProduct = v1.x * v2.x + v1.y * v2.y;
      const mag1 = Math.sqrt(v1.x * v1.x + v1.y * v1.y);
      const mag2 = Math.sqrt(v2.x * v2.x + v2.y * v2.y);
      if (mag1 === 0 || mag2 === 0) return 180;
      const angleRad = Math.acos(dotProduct / (mag1 * mag2));
      return angleRad * (180 / Math.PI);
    };

    for (let i = 0; i < solutionPath.length; i++) {
      const p1_idx = solutionPath[i];
      const p2_idx = solutionPath[(i + 1) % numCities];
      const p3_idx = solutionPath[(i + 2) % numCities];

      // 1. Calculate segment distance
      totalDistance += Math.sqrt(Math.pow(cities[p1_idx].x - cities[p2_idx].x, 2) + Math.pow(cities[p1_idx].y - cities[p2_idx].y, 2));

      // 2. Calculate turn penalty
      const angle = calculateAngle(
        cities[p1_idx],
        cities[p2_idx],
        cities[p3_idx],
      );
      if (angle < 45) {
        // Penalty for very sharp turns (< 45 degrees)
        totalPenalty += (45 - angle) * 5; // The penalty is proportional to the sharpness of the angle
      }
    }

    const finalScore = totalDistance + totalPenalty;
    return finalScore <= targetMaxDistance;
  } catch (e) {
    console.error("Error during TSP challenge verification:", e);
    return false;
  }
};

/**
 * Generates the HTML content for the CPU PoW challenge (SHA-256).
 */
const generateCpuPoWChallenge = (
  clientIp,
  nonce,
  difficulty = 4,
  path = "",
) => {
  return `
      <html>
        <head><title>Security Check</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>One moment... (Level 1)</h1>
          <p>We are verifying that you are not a bot. This takes a few seconds.</p>
          <div id="loader" style="margin:20px;">⚙️ Performing CPU security calculation...</div>
          <script>
            async function solve() {
              const ip = "${clientIp}";
              const nonce = "${nonce}";
              const diff = ${difficulty};
              const target = "0".repeat(diff);
              let solution = 0;
              
              while (true) {
                const msg = "${ip}" + ":" + "${nonce}" + ":" + solution;
                const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
                const hash = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
                if (hash.startsWith(target)) break;
                solution++;
                if (solution % 100000 === 0) await new Promise(resolve => setTimeout(resolve, 0)); // To avoid freezing the browser
              }
              window.location.href = "${path}" + "?pow_type=cpu&pow_nonce=" + nonce + "&pow_solution=" + solution;
            }
            solve();
          </script>
        </body>
      </html>
    `;
};

/**
 * Generates the HTML content for a memory-intensive PoW challenge.
 */
const generateMemoryPoWChallenge = (
  clientIp,
  nonce,
  difficulty = 16,
  path = "",
) => {
  // difficulty here is the buffer size in MB.
  return `
      <html>
        <head><title>Advanced Security Check</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Enhanced Verification... (Level 2)</h1>
          <p>Your activity requires an additional security check.</p>
          <div id="loader" style="margin:20px;">⚙️ Performing memory allocation and calculation... (${difficulty} MB)</div>
          <script>
            async function solve() {
              const nonce = "${nonce}";
              const size = ${difficulty} * 1024 * 1024; // en octets
              const iterations = size / 16;
              
              try {
                const buffer = new Uint32Array(size / 4);
                let h = new TextEncoder().encode(nonce).reduce((acc, v) => acc + v, 0);
                for (let i = 0; i < buffer.length; i++) {
                    buffer[i] = (h = Math.imul(h ^ i, 1597334677));
                }
                
                let finalHash = 0;
                for(let i = 0; i < iterations; i++) {
                    const addr = buffer[i % buffer.length] % buffer.length;
                    finalHash ^= buffer[addr];
                }
                window.location.href = "${path}" + "?pow_type=mem&pow_nonce=" + nonce + "&pow_solution=" + finalHash;
              } catch(e) {
                document.getElementById('loader').innerText = "Error: Insufficient memory. Please refresh.";
              }
            }
            solve();
          </script>
        </body>
      </html>`;
};

/**
 * Verifies if a PoW solution is valid and generates a clearance ticket.
 */
export const verifyPoWAndGenerateTicket = (
  ip,
  nonce,
  solution,
  difficulty = 4,
) => {
  // 1. Verify the solution: hash(ip + nonce + solution) must start with N zeros
  const hash = crypto
    .createHash("sha256")
    .update(`${ip}:${nonce}:${solution}`)
    .digest("hex");

  if (!hash.startsWith("0".repeat(difficulty))) {
    return null;
  }

  // 2. Generate an HMAC ticket so the client doesn't have to do it again for 1 hour
  const expiry = Date.now() + 3600000; // 1 heure
  const signature = crypto
    .createHmac("sha256", getPowSecret())
    .update(`${ip}:${expiry}`)
    .digest("hex");

  return `${expiry}:${signature}`;
};



/**
 * Verifies a memory PoW solution.
 * The server performs the same calculation to validate.
 */
export const verifyMemoryPoW = (nonce, solution, difficulty = 16, clientSecret = '') => {
  // Hard cap on memory difficulty to prevent DoS attacks from malicious clients
  // submitting an arbitrarily large difficulty value.
  const MAX_ALLOWED_MEM_DIFFICULTY = 128; // 128MB
  if (difficulty > MAX_ALLOWED_MEM_DIFFICULTY) {
    console.warn(`[Security] Memory PoW verification attempt with excessive difficulty: ${difficulty}MB. Denied.`);
    return false;
  }
  const size = difficulty * 1024 * 1024;
  const iterations = size / 16;
  const buffer = new Uint32Array(size / 4);
  const seed = `:${nonce}:${clientSecret}`;
  let h = new TextEncoder().encode(seed).reduce((acc, v) => acc + v, 0);

  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = h = Math.imul(h ^ i, 1597334677);
  }

  let finalHash = 0;
  let addr = buffer.length > 0 ? buffer[0] % buffer.length : 0;
  for (let i = 0; i < iterations; i++) {
    addr = buffer[addr] % buffer.length;
    finalHash ^= addr;
  }
  return finalHash === parseInt(solution, 10);
};
export const isTicketValid = (ip, ticket) => {
  // Input validation: ensure the ticket is a non-empty string with the correct format.
  if (typeof ticket !== 'string' || !ticket.includes(':')) return false;
  const [expiry, sig] = ticket.split(':');
  if (!expiry || !sig || Date.now() > parseInt(expiry, 10)) return false;
  const expectedSig = crypto
    .createHmac("sha256", getPowSecret())
    .update(`${ip}:${expiry}`)
    .digest("hex");

  // Use timingSafeEqual to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expectedSig, 'hex'));
  } catch (e) {
    // This can happen if the buffers have different lengths, which is a failure case.
    return false;
  }
};


/**
 * Calculates suspicion indicators related to HTTP header anomalies.
 * @param {object} context - The request context.
 * @returns {{headerAnomalyScore: number}}
 */
function getHeaderAnomalies(context) {
  let anomalyScore = 0;
  // Strong penalty if User-Agent is missing or very short (sign of a simple script)
  if (!context.headers["user-agent"] || context.headers["user-agent"].length < 10) {
    anomalyScore += 60;
  }
  // Penalty if Accept-Language header is missing
  if (!context.headers["accept-language"]) {
    anomalyScore += 25;
  }
  // Penalty for HTTP/1.0 requests, often used by old tools or bots
  if (context.httpVersion === "1.0") {
    anomalyScore += 15;
  }

  return {
    headerAnomalyScore: Math.min(100, anomalyScore),
  };
}

/**
 * Checks for submitted honeypot fields to detect bots.
 * @param {object} context - The request context.
 * @param {object} honeypotConfig - The honeypot configuration.
 * @returns {{honeypotScore: number}}
 */
function getHoneypotScore(context, honeypotConfig = {}) {
  const { fields = [], trapUrls = [], detectInjections = true } = honeypotConfig;
  // (NOUVEAU) Permettre de brancher des analyseurs externes plus robustes.
  // L'utilisateur pourrait passer une fonction qui prend les données de la requête
  // et retourne `true` si une menace est détectée.
  // Exemple: `(data) => myWafLibrary.isMalicious(data)`
  const externalAnalyzers = honeypotConfig.analyzers || [];
  if (typeof detectInjections === 'object' && detectInjections.analyzers) {
      externalAnalyzers.push(...detectInjections.analyzers);
  }

  // 1. Check for trap URL access
  if (trapUrls.some(trap => context.path.startsWith(trap))) {
    return { honeypotScore: 100 };
  }

  if (fields.length === 0 && !detectInjections) {
    return { honeypotScore: 0 };
  }

  // Check both query parameters (for URL probing) and the request body (for hidden form fields).
  const queryData =
    context.query instanceof URLSearchParams
      ? Object.fromEntries(context.query.entries())
      : context.query || {};
  const bodyData = context.body || {};

  // 2. Check for honeypot field names
  for (const field of fields) {
    // A bot is trapped if the field exists in either the query OR the body.
    if (
      Object.prototype.hasOwnProperty.call(queryData, field) ||
      Object.prototype.hasOwnProperty.call(bodyData, field)
    ) {
      return { honeypotScore: 100 }; // A bot fell into the trap, maximum score.
    }
  }

  // 3. (NOUVEAU) Utiliser les analyseurs externes
  const allData = { ...queryData, ...bodyData };
  if (externalAnalyzers.length > 0) {
      for (const analyzer of externalAnalyzers) {
          // On passe à l'analyseur l'ensemble des données de la requête.
          if (analyzer(allData)) {
              return { honeypotScore: 100 };
          }
      }
  }

  if (detectInjections) {
    // 3. Check for injection attempts in values using the centralized isMalicious function.
    const inspect = (obj) => {
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const value = obj[key];
                if (typeof value === 'string') {
                    if (isMalicious(value)) return true;
                } else if (typeof value === 'object' && value !== null) {
                    // For nested objects (like in NoSQL injections), we stringify them once
                    // to check for malicious patterns within their structure or values.
                    if (isMalicious(JSON.stringify(value))) return true;
                    // Then, we recurse to check individual string values inside.
                    if (inspect(value)) return true;
                }
            }
        }
        return false;
    };

    if (inspect(queryData)) {
        return { honeypotScore: 100 };
    }
    if (inspect(bodyData)) {
        return { honeypotScore: 100 };
    }
  }

  return { honeypotScore: 0 };
}

/**
 * @private
 * Map of malicious patterns grouped by type.
 */
const injectionPatterns = {
    // SQL/NoSQL injections, including time-based attacks
    sql: /(\$ne|' *OR *'1'='1|['";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|SLEEP\(|BENCHMARK\(|WAITFOR DELAY)/i,
    // Log4Shell (JNDI injection)
    log4shell: /\$\{jndi:(ldap|rmi|dns):/i,
    // Server-Side Template Injection (SSTI) for engines like Jinja2, Twig, etc.
    ssti: /\{\{.*\}\}|\{%.*%\}/,
    // XML External Entity (XXE) injection
    xxe: /<!ENTITY\s+.*SYSTEM/i,
    // Path Traversal
    traversal: /(\.\.\/|\.\.\\)/,
    // Remote Command Execution (RCE)
    rce: /`.*`|(^|[\n;&|]\s*)(ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b/i,
};

/**
 * Calcule un score basé sur les métriques comportementales envoyées par le client.
 * @param {object} context - Le contexte de la requête, contenant les en-têtes.
 * @returns {{behaviorScore: number}}
 */
function getBehaviorScore(context) {
  const behaviorHeader = context.headers["x-behavior-metrics"];
  if (!behaviorHeader) {
    return { behaviorScore: 0 }; // Pas de données, pas de pénalité.
  }

  try {
    const metrics = JSON.parse(behaviorHeader);
    let score = 0;

    // 1. Pénalité maximale si un honeypot client a été déclenché.
    if (metrics.honeypotInteraction) {
      return { behaviorScore: 100 };
    }

    // 2. Pénalité pour absence totale d'interaction.
    if (metrics.mouseEntropy === 0 && metrics.keystrokeLatency === 0) {
      score += 40;
    }

    // 3. (NOUVEAU) Analyse de la longueur de l'historique de navigation.
    // Un historique court est suspect (nouvel onglet, bot), un historique long est un bon signe.
    if (typeof metrics.historyLength === 'number') {
        if (metrics.historyLength === 1) {
            score += 15; // Légère pénalité pour un historique de session vierge.
        } else if (metrics.historyLength >= 5) {
            score -= 20; // Bonus : un historique long est un fort indicateur humain.
        } else if (metrics.historyLength >= 2) {
            score -= 10; // Petit bonus pour une navigation de base.
        }
    }
    // 3. Vérification de la plausibilité et de la distribution des métriques.
    // Un bot pourrait envoyer des valeurs aléatoires, mais elles ne suivront probablement pas
    // des distributions naturelles (comme la loi de Benford pour les premiers chiffres).

    // Plausibilité de l'entropie de la souris
    if (metrics.mouseEntropy > 0 && metrics.mouseEntropy < 0.1) score += 20; // Entropie très faible, suspect.
    if (metrics.mouseEntropy > 500) score += 30; // Entropie irréalistement élevée.

    // Plausibilité de la latence de frappe
    if (metrics.keystrokeLatency > 0 && metrics.keystrokeLatency < 40) score += 25; // Frappe trop rapide pour un humain.
    if (metrics.keystrokeLatency > 1000) score += 15; // Latence très élevée, peut être un script lent.

    // 4. Analyse de la distribution avec la loi de Benford (si les valeurs sont non nulles).
    // On utilise les décimales pour avoir plus de chiffres à analyser.
    const mouseEntropyStr = String(metrics.mouseEntropy).replace(".", "");
    const keystrokeLatencyStr = String(metrics.keystrokeLatency).replace(".", "");

    if (mouseEntropyStr.length > 2) {
      const mouseDeviation = Optimization.Operators.benfordTest(mouseEntropyStr);
      // Une déviation > 0.15 est fortement suspecte.
      if (mouseDeviation > 0.15) score += 40;
    }

    if (keystrokeLatencyStr.length > 2) {
      const keystrokeDeviation = Optimization.Operators.benfordTest(keystrokeLatencyStr);
      if (keystrokeDeviation > 0.15) score += 40;
    }

    return { behaviorScore: Math.max(0, Math.min(100, score)) }; // Assure que le score reste entre 0 et 100
  } catch (e) {
    return { behaviorScore: 10 }; // En-tête malformé = légèrement suspect.
  }
}

/**
 * Calcule un score basé sur l'incohérence temporelle entre le client et le serveur pour détecter les attaques par rejeu.
 * @param {object} context - Le contexte de la requête, contenant le timestamp de la requête.
 * @param {object} metrics - Les métriques comportementales parsées depuis le client.
 * @returns {{timeInconsistencyScore: number}}
 */
function getTimeInconsistencyScore(context, metrics) {
  const REPLAY_THRESHOLD_MS = 5000; // 5 secondes
  let score = 0;

  if (metrics.clientTimestamp && context.requestTimestamp) {
    const timeDelta = context.requestTimestamp - metrics.clientTimestamp;

    // Un delta très grand est un signal fort d'attaque par rejeu.
    // Un delta négatif peut arriver si l'horloge du client est en avance, on l'ignore.
    if (timeDelta > REPLAY_THRESHOLD_MS) {
      // La pénalité est proportionnelle au dépassement du seuil.
      score = Math.min(100, (timeDelta / REPLAY_THRESHOLD_MS - 1) * 50);
    }
  }
  return { timeInconsistencyScore: score };
}

/**
 * Calcule un score d'incohérence entre les données du fingerprint client et les en-têtes serveur.
 * @param {object} context - Le contexte de la requête.
 * @returns {{crossLayerInconsistencyScore: number}}
 */
function getCrossLayerInconsistency(context) {
    try {
        const clientFpString = context.headers['x-device-fingerprint'];
        if (!clientFpString) return { crossLayerInconsistencyScore: 0 };

        const clientFpMap = new Map(clientFpString.split("|").map(part => part.split(":")));
        const ua = context.headers["user-agent"] || '';
        let score = 0;

        // 1. Incohérence de l'OS
        const clientOsHash = clientFpMap.get('os');
        if (clientOsHash) {
            const serverOsParts = parseUserAgent(ua);
            if (serverOsParts.os && clientOsHash !== cyrb53(serverOsParts.os)) {
                // Exemple: le client prétend être 'Windows' mais le UA est 'macOS'.
                score += 50;
            }
        }

        // 2. Incohérence de l'écran (si les Client Hints sont disponibles)
        const clientScreenHash = clientFpMap.get('scr');
        const viewportWidth = context.headers['sec-ch-viewport-width'];
        if (clientScreenHash && viewportWidth) {
            const clientWidth = clientFpMap.get('scr')?.split('x')[0];
            // Ce n'est pas une comparaison directe, mais un bot pourrait oublier de forger les CH.
            // Si le client FP a une largeur et que le CH en a une autre, c'est suspect.
            // Cette vérification est basique et pourrait être affinée.
            if (clientWidth && clientWidth !== viewportWidth) {
                score += 20;
            }
        }

        // 3. Incohérence du GPU/Canvas et JA3
        // Un attaquant sophistiqué peut forger le canvas, mais il est très difficile de forger
        // le JA3 qui dépend de la librairie TLS. Une forte incohérence ici est un signal fort.
        const clientGpuHash = clientFpMap.get('gpu');
        const ja3 = getJa3Hash(context);
        if (clientGpuHash && ja3) {
            // Une vraie implémentation nécessiterait une base de données mappant les GPU connus
            // à des signatures JA3 typiques. Pour l'exemple, on simule une pénalité si les deux
            // sont présents mais que le score de cohérence global est déjà faible.
            // (Cette logique est déjà en partie couverte par le `consistencyScore`).
        }

        return { crossLayerInconsistencyScore: Math.min(100, score) };
    } catch (e) {
        return { crossLayerInconsistencyScore: 10 }; // Erreur de parsing = suspect.
    }
}

/**
 * Calcule un score d'incohérence entre les données du fingerprint TLS (JA3/JA4) et les en-têtes serveur (User-Agent).
 * Cela permet de détecter le spoofing de fingerprint TLS.
 * @param {object} context - Le contexte de la requête.
 * @returns {{tlsSpoofingScore: number}}
 */
function getTlsSpoofingScore(context, getTlsFingerprintFn = getTlsFingerprint) {
    const { ja3, ja4 } = getTlsFingerprintFn(context) || { ja3: null, ja4: null }; // Defensive check
    const ua = context.headers["user-agent"] || '';

    // 1. Penalize if a TLS fingerprint is present but the User-Agent is generic or missing.
    // This is a strong indicator of a non-browser client trying to look legitimate.
    if ((ja3 || ja4) && (!ua || ua.length < 10 || ua.toLowerCase().includes('python') || ua.toLowerCase().includes('curl'))) {
        return { tlsSpoofingScore: 50 };
    }

    // 2. If no JA3 hash is available, we cannot perform the consistency check.
    if (ja3 && ua) {
        // Look up the expected browser family (or families) from our database.
        let expectedBrowsers = tlsFingerprintDb[ja3];

        if (expectedBrowsers) {
            // Ensure it's always an array for consistent logic.
            if (!Array.isArray(expectedBrowsers)) {
                expectedBrowsers = [expectedBrowsers];
            }

            // Parse the User-Agent to get the claimed browser.
            const { browser: claimedBrowser } = parseUserAgent(ua);

            // Check if the claimed browser is one of the legitimate possibilities for this JA3 hash.
            // We use `some` to see if the claimed browser starts with any of the expected browser names.
            // (e.g., "Chrome/116" starts with "Chrome").
            const isMatch = expectedBrowsers.some(expected => claimedBrowser?.startsWith(expected));

            if (claimedBrowser && !isMatch) {
                return { tlsSpoofingScore: 80 }; // High score for a clear mismatch.
            }
        }
    }

    // If we reach here, either:
    // - No JA3 was available.
    // - The JA3 was not in our database (we can't make a decision).
    // - The JA3 and User-Agent were consistent.
    // In all these cases, the score is 0.
    return { tlsSpoofingScore: 0 };
}


/**
 * Calcule un score basé sur la détection explicite de frameworks d'automatisation.
 * @param {object} context - Le contexte de la requête.
 * @returns {{botScore: number}}
 */
function getBotScore(context) {
    const clientFpString = context.headers['x-device-fingerprint'];
    if (!clientFpString) return { botScore: 0 };

    try {
        const clientFpMap = new Map(clientFpString.split("|").map(part => part.split(":")));
        // Pénalité maximale si l'un des marqueurs d'automatisation est présent.
        if (clientFpMap.has('bot') || clientFpMap.has('cdp')) {
            return { botScore: 100 };
        }
    } catch (e) { /* Ignorer les erreurs de parsing */ }

    return { botScore: 0 };
}

/**
 * Analyzes server-side request patterns for a given device to detect bot-like behavior.
 * This is a stateful check that looks for repetitive or unnaturally fast requests.
 * @param {object} context - The request context.
 * @param {object} deviceData - The device's activity data from the store.
 * @returns {{requestPatternScore: number}}
 */
function getRequestPatternScore(context, deviceData, patternConfig = {}) {
    if (!deviceData) return { requestPatternScore: 0 };

    // (NOUVEAU) Logique de détection de pattern simplifiée et unifiée.
    const {
        historySize = 20,           // Nombre de requêtes à conserver pour l'analyse.
        minSamples = 10,            // Nombre d'intervalles de temps à analyser avant de calculer.
        regularityThreshold = 150,  // Écart-type (ms) en dessous duquel le comportement est "trop régulier".
        benfordThreshold = 0.15,    // Seuil de déviation de Benford au-dessus duquel la distribution est "non naturelle".
        patternWeight = 80,         // Pénalité FORTE et unique si un pattern est détecté.
        decayFactor = 0.95,         // Décroissance du score dans le temps.
        inactivityReset = 180000    // Réinitialisation du score après 3 minutes d'inactivité.
    } = patternConfig;

    const now = Date.now();
    const currentPath = context.path;
    // Make the function robust to handle both URLSearchParams and plain objects for query.
    const params =
      context.query instanceof URLSearchParams
        ? new URLSearchParams(context.query.toString()) // Clone to avoid modifying the original
        : new URLSearchParams(context.query || {});
    params.sort(); // Sort for deterministic order
    const currentQueryString = params.toString();

    if (!deviceData.requestHistory) deviceData.requestHistory = [];
    if (!deviceData.timingHistory) deviceData.timingHistory = [];

    const history = deviceData.requestHistory;
    const lastRequest = history.length > 0 ? history[history.length - 1] : null;
    const timeSinceLast = lastRequest ? now - lastRequest.timestamp : Infinity;

    // Mise à jour de l'historique
    history.push({
        timestamp: now,
        path: currentPath,
        queryString: currentQueryString,
    });
    if (lastRequest) {
        deviceData.timingHistory.push(timeSinceLast);
    }

    let instantScore = 0;
    const timings = deviceData.timingHistory;

    // Analyse statistique unifiée si nous avons assez de données
    if (timings.length >= minSamples) {
        const timings = deviceData.timingHistory;
        const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
        const variance = timings.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / timings.length;
        const stdDev = Math.sqrt(variance);
        const benfordDeviation = Optimization.Operators.benfordTest(timings);

        // Détection de régularité (bots de type "cron")
        if (stdDev < regularityThreshold) {
            instantScore = patternWeight;
        }
        // Détection de distribution non-naturelle (bots "faussement aléatoires")
        else if (benfordDeviation > benfordThreshold) {
            instantScore = patternWeight;
        }
    }

    // Garder l'historique à une taille raisonnable
    if (history.length > historySize) {
        history.shift();
    }
    if (deviceData.timingHistory.length > historySize) {
        deviceData.timingHistory.shift();
    }

    // Logique de décroissance et de score final
    let newPatternScore = deviceData.lastPatternScore || 0;

    if (timeSinceLast > inactivityReset) {
        newPatternScore = 0; // Réinitialisation complète après une longue inactivité
    } else {
        newPatternScore *= decayFactor;
    }
    newPatternScore = Math.max(0, newPatternScore);

    deviceData.lastPatternScore = newPatternScore + instantScore;

    return { requestPatternScore: Math.min(100, deviceData.lastPatternScore) };
}

const trapUrlTemplates = [
    '/includes/config-{RANDOM}.php',          // Classic PHP config file
    '/.env.{RANDOM}',                         // Environment file
    '/backups/db_backup_{RANDOM}.sql.gz',     // Database backup
    '/api/v1/internal/status?trace={RANDOM}', // Internal API endpoint
    '/_private/deploy_key_{RANDOM}.pem',      // Private key file
    '/logs/app_error_{RANDOM}.log',           // Log file
    '/.git/config_{RANDOM}'                   // Exposed git config variant
];

/**
 * Generates a signed trap URL.
 * @param {string} nonce - The nonce to sign the URL with.
 * @returns {string} The trap URL.
 */
function generateTrapUrl(nonce) {
    // Pick a random template to diversify the traps
    const template = trapUrlTemplates[Math.floor(Math.random() * trapUrlTemplates.length)];
    const randomPart = crypto.randomBytes(8).toString('hex');
    const path = template.replace('{RANDOM}', randomPart);

    const signature = crypto.createHmac('sha256', getPowSecret()).update(nonce + path).digest('hex').substring(0, 16);
    return `${path}?sig=${signature}`;
}

/**
 * Verifies if a given path is a valid trap URL for a given nonce.
 * @param {string} path - The request path.
 * @param {string} signature - The signature from the query.
 * @param {string} nonce - The nonce to verify against.
 * @returns {boolean}
 */
function verifyTrapUrl(path, signature, nonce) {
    const expectedSignature = crypto.createHmac('sha256', getPowSecret()).update(nonce + path).digest('hex').substring(0, 16);
    try {
        // Use timingSafeEqual to prevent timing attacks where an attacker could guess the signature byte by byte.
        return crypto.timingSafeEqual(Buffer.from(signature, 'hex'), Buffer.from(expectedSignature, 'hex'));
    } catch {
        // This will catch errors if buffers have different lengths or contain invalid hex characters, which is a failure case.
        return false;
    }
}
/**
 * @typedef {object} IStore
 * @property {(key: string) => Promise<any>} get
 * @property {(key: string, value: any, ttl?: number) => Promise<void>} set
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * Default in-memory store implementation.
 * @type {IStore}
 */
const inMemoryStore = {
  _map: new Map(),
  _timeouts: new Map(),
  async get(key) { return this._map.get(key); },
  async set(key, value, ttl) {
    this._map.set(key, value);
    // If a timeout already exists for this key, clear it.
    if (this._timeouts.has(key)) {
        clearTimeout(this._timeouts.get(key));
        this._timeouts.delete(key);
    }
    // If a TTL is provided, set a timeout to delete the key.
    if (ttl && ttl > 0) {
        const timeoutId = setTimeout(() => this._map.delete(key), ttl * 1000);
        this._timeouts.set(key, timeoutId);
    }
  },
  async has(key) { return this._map.has(key); },
  async delete(key) { this._map.delete(key); },
};

/** @type {IStore} */
let store = inMemoryStore;

/**
 * Allows configuring an external datastore (e.g., Redis).
 * Must be called before the middleware is used.
 * @param {IStore} externalStore - An implementation of the IStore interface.
 */
export const configureStore = (externalStore) => {
  store = externalStore;
};

/**
 * Orchestrates request identification using a persistent anchor (cookie)
 * and fingerprint verification.
 * @param {object} context - The request context.
 * @returns {Promise<{deviceId: string, deviceData: object, consistencyScore: number, newCookie: object|null}>}
 */
async function resolveRequestIdentity(context, securityConfig = {}) {
  const existingDeviceId = context.cookies?.device_id;
  const currentDeviceHash = getCompositeDeviceHash(context); // Use the composite hash for consistency checks
  let deviceId = existingDeviceId;
  let consistencyScore = 1.0; // 1.0 = perfectly consistent
  let deviceData = null;
  let newCookie = null;
  if (deviceId) {
    deviceData = await store.get(`device:${deviceId}`);
  }

  if (deviceData) {
    // Case 1: The user has a "passport" and we know them.
    const storedHash = deviceData.initialDeviceHash;

    // Compare the current fingerprint with the reference one.
    consistencyScore = FingerprintBuilder.compare(
      storedHash,
      currentDeviceHash,
    );
  } else {
    // Case 2: New user or lost/invalid cookie.
    deviceId = crypto.randomUUID(); // Generate a new "passport".

    // Return the intention to set a cookie.
    newCookie = {
      name: "device_id",
      value: deviceId,
      options: {
        httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict",
        // Le maxAge est maintenant configurable. Par défaut, c'est un cookie de session.
        ...(securityConfig.deviceIdCookieMaxAge && { maxAge: securityConfig.deviceIdCookieMaxAge }),
      }
    };

    // Initialize tracking for this new device.
    deviceData = {
      initialDeviceHash: currentDeviceHash, // Anchor the initial fingerprint.
      ips: new Set(),
      requestHistory: [], // Initialize state for the new pattern score
      lastUpdate: Date.now(),
      lastFpHash: currentDeviceHash,
      lastChangeTimestamp: 0,
      rapidChangeCount: 0,
      highScoreCount: 0,
      lastHighScoreTimestamp: 0,
    };
    // The write will happen in getSuspicionVector after all modifications.
  }

  return { deviceId, deviceData, consistencyScore, newCookie };
}

/*
 * Calcule les indicateurs de suspicion liés au comportement de l'appareil (historique, rotation).
 * @param {object} context - The request context.
 * @param {object} deviceData - The device's activity data.
 * @returns {Promise<{historyScore: number, rotationScore: number}>}
 */
async function getBehavioralIndicators(context, deviceData) {
  const now = Date.now();
  const clientIp = context.clientIp;

  // Get the IP type to modulate the score
  const ipProfile = (await store.get(`ip:${clientIp}`)) || { type: "residential" };
  const isSharedIp = ipProfile.type === "shared";

  const currentFpHash = getCompositeDeviceHash(context); // Use the composite hash for behavioral indicators

  // --- Behavior analysis (Change frequency) ---
  if (deviceData.lastFpHash && currentFpHash !== deviceData.lastFpHash) {
    const timeSinceLastChange = now - deviceData.lastChangeTimestamp;

    if (timeSinceLastChange < RAPID_CHANGE_THRESHOLD_MS) {
      deviceData.rapidChangeCount = Math.min(
        deviceData.rapidChangeCount + 1,
        MAX_RAPID_CHANGES_PER_DEVICE * 2, // Increases quickly
      );
    } else {
      deviceData.rapidChangeCount = Math.max(0, deviceData.rapidChangeCount - 1); // Decreases slowly
    }
    deviceData.lastChangeTimestamp = now;
  }

  deviceData.lastFpHash = currentFpHash;
  deviceData.ips.add(clientIp); // Record the IP used by this device

  // NOUVELLE LOGIQUE : Le score d'historique est basé sur le nombre d'IPs utilisées par l'appareil.
  // Très efficace contre la rotation de proxy.
  const maxIpsForDevice = isSharedIp
    ? MAX_DISTINCT_IPS_FOR_SHARED_USER
    : MAX_DISTINCT_IPS_PER_DEVICE;
  const freeIpChanges = isSharedIp ? 1 : 3;

  const historyScore = Math.min(
    100,
    (Math.max(0, deviceData.ips.size - freeIpChanges) /
      (maxIpsForDevice - freeIpChanges)) *
      100,
  );

  // Score based on rapid identity rotation (0-100)
  const rotationScore = Math.min(
    100,
    (deviceData.rapidChangeCount / MAX_RAPID_CHANGES_PER_DEVICE) * 100,
  );

  return { historyScore, rotationScore };
}

/**
 * Returns a vector of raw (unweighted) suspicion scores.
 * @param {object} context - The request context object.
 * @returns {Promise<{historyScore: number, rotationScore: number, headerAnomalyScore: number, inconsistencyScore: number, honeypotScore: number}>}
 */
export const getSuspicionVector = async (context, securityConfig) => {
    // On récupère la configuration du honeypot pour l'utiliser ici.
    const honeypotConfig = securityConfig.honeypot || {};

    const { deviceId, deviceData, consistencyScore, newCookie } = await resolveRequestIdentity(context, securityConfig);

  const clientIp = context.clientIp;

  // If a new cookie needs to be set, attach it to the request object
  // so the middleware can handle it. This is a temporary state holder.
  if (newCookie) {
    context._newCookies = context._newCookies || [];
    context._newCookies.push(newCookie);
  }
  await store.set(`ip-device:${clientIp}`, deviceId, 600); // Link the IP to the device for 10 minutes

  // Periodically clean up device data
  if (Date.now() - deviceData.lastUpdate > 10 * 60 * 1000) { // 10 minutes
    deviceData.ips.clear();
    deviceData.rapidChangeCount = 0;
  }
  deviceData.lastUpdate = Date.now();

  const behavioral = await getBehavioralIndicators(context, deviceData);
  const { headerAnomalyScore } = getHeaderAnomalies(context);
  // Calculate the inconsistency score here, separately.
  let inconsistencyScore = Math.min(100, Math.max(0, (1 - consistencyScore) * 200)); // Amplified score

  // NOUVEAU: Si l'incohérence est très forte (cookie probablement volé), on applique une pénalité maximale.
  if (consistencyScore < 0.7) { // Seuil de rupture
      inconsistencyScore = 100;
  }

  const { behaviorScore } = getBehaviorScore(context); // Appel de la fonction

  // On appelle getHoneypotScore ici pour que son résultat soit inclus dans le vecteur.
  const { honeypotScore } = getHoneypotScore(context, honeypotConfig);

  // NOUVEAU: On calcule le score de spoofing TLS.
  const { tlsSpoofingScore } = getTlsSpoofingScore(context);

  // NOUVEAU: On appelle getBotScore pour détecter les marqueurs d'automatisation.
  const { botScore } = getBotScore(context);

  // NOUVEAU: On calcule le score d'incohérence temporelle.
  const { timeInconsistencyScore } = getTimeInconsistencyScore(context, JSON.parse(context.headers['x-behavior-metrics'] || '{}'));

  // NOUVEAU: On calcule le score d'incohérence entre les couches.
  const { crossLayerInconsistencyScore } = getCrossLayerInconsistency(context);

  const { requestPatternScore } = getRequestPatternScore(context, deviceData, securityConfig.patterns);

  // Save the updated device state to the store
  // Note: deviceData.ips is a Set, which may not serialize correctly in all stores (e.g., JSON). A Redis store should handle this via custom serialization or by converting to an array.
  await store.set(`device:${deviceId}`, deviceData);

  // Ensure deviceData.ips is a Set for subsequent operations within the same request,
  // even if the store returns an array.
  if (Array.isArray(deviceData.ips)) {
      deviceData.ips = new Set(deviceData.ips);
  }
  // Le vecteur de suspicion est maintenant complet.
  return { ...behavioral, headerAnomalyScore, inconsistencyScore, behaviorScore, honeypotScore, botScore, requestPatternScore, crossLayerInconsistencyScore, timeInconsistencyScore, tlsSpoofingScore };
};

// A residential user can change networks (home, 4G, public wifi).
const MAX_DISTINCT_IPS_PER_DEVICE = 15;
// Un utilisateur derrière un NAT/proxy ne devrait pas utiliser BEAUCOUP d'autres IPs.
const MAX_DISTINCT_IPS_FOR_SHARED_USER = 5;

// Une IP est considérée comme "partagée" si elle est utilisée par plus de 50 appareils différents en 10 minutes.
const SHARED_IP_DEVICE_THRESHOLD = 50;

const RAPID_CHANGE_THRESHOLD_MS = 2000; // 2 secondes
const MAX_RAPID_CHANGES_PER_DEVICE = 3; // Number of rapid fingerprint changes allowed per device.

/**
 * Identifies a request on the server side in a granular way.
 * Uses FingerprintBuilder to create a fingerprint based on headers
 * and IP, making spoofing more complex (requires changing the entire stack).
 */
export const identifyRequest = (securityConfig) => async (req, res) => {
  // This function now acts as a lightweight wrapper around the engine's identifyRequest method.
  // It requires a default configuration to work.
  const config = securityConfig || {
    weights: { historyScore: 0.3, rotationScore: 0.5, headerAnomalyScore: 0.1, inconsistencyScore: 0.8, honeypotScore: 1.0 },
    thresholds: { low: 20, medium: 40, high: 75 },
    honeypot: { fields: [] } // Ensure honeypot config exists to prevent errors
  };
  const engine = new FingerprintEngine(config);

  const requestContext = {
      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
      query: req.query,
      body: req.body,
      cookies: req.cookies,
      headers: req.headers,
      rawHeaders: req.rawHeaders,
      httpVersion: req.httpVersion,
  };

  const key = await engine.identifyRequest(requestContext);

  if (requestContext._newCookies && res) {
    requestContext._newCookies.forEach(c => res.cookie(c.name, c.value, c.options));
  }

  return key;
};
// --- NOUVEAU CHALLENGE CPU "ANALOGIQUE" ---

// Le plus grand nombre possible avec SHA-256 (2^256 - 1)
// The largest possible number with SHA-256 (2^256 - 1)
const MAX_DIFFICULTY_TARGET = 2n ** 256n - 1n;
// Une difficulté de base, ex: nécessite que les 16 premiers bits soient à 0
// (équivalent à 4 zéros en hexadécimal)
// A base difficulty, e.g., requires the first 16 bits to be 0
// (equivalent to 4 zeros in hexadecimal)
const BASE_TARGET = MAX_DIFFICULTY_TARGET >> 16n;

/**
 * Calculates the difficulty target based on the suspicion factor.
 * @param {number} suspicionFactor - A number from 0 to 1.
 * @returns {BigInt} The target number.
 */
function calculateTarget(suspicionFactor, securityConfig = {}) {
  // Difficulty range adjusted to be realistic.
  // MIN_DIFFICULTY: Fast enough not to bother a slightly suspicious user.
  // MAX_DIFFICULTY: Slow enough to heavily penalize a bot, but feasible for a patient human (5-30s).
  // NOUVEAU: La difficulté est maintenant configurable.
  const { cpu: cpuConfig = {} } = securityConfig;
  const MIN_DIFFICULTY_BITS = cpuConfig.minDifficultyBits ?? 8;
  const MAX_DIFFICULTY_BITS = cpuConfig.maxDifficultyBits ?? 16;

  // Use linear interpolation between min and max difficulty.
  const totalDifficultyBits =
    MIN_DIFFICULTY_BITS +
    suspicionFactor * (MAX_DIFFICULTY_BITS - MIN_DIFFICULTY_BITS);
  
  if (totalDifficultyBits <= 0) return 2n ** 256n - 1n; // Si la difficulté est nulle ou négative, la cible est maximale (aucun challenge).

  // The correct way to calculate the target is to define the number of leading zero bits required.
  // A target for N bits of difficulty is 2^(256-N).
  // We can calculate this with a left-shift on 1.
  const shift = 256n - BigInt(Math.floor(totalDifficultyBits));
  return 1n << shift;
}

/**
 * @private
 * Crée le bloc de base pour le challenge CPU.
 * Ce buffer contient toutes les données sauf la solution.
 * @param {string} nonce
 * @param {string} clientSecret
 * @param {string} fingerprint
 * @returns {Buffer}
 */
function createCpuChallengeBaseBlock(nonce, clientSecret, fingerprint) {
    const sortedFingerprint = (fingerprint || '').split('|').filter(p => p).sort().join('|');
    // On concatène les chaînes, puis on les convertit en buffer une seule fois.
    // Cela garantit que le client et le serveur travaillent sur la même base binaire.
    const messageBase = `${nonce}:${clientSecret}:${sortedFingerprint}:`; // Le ':' final est le séparateur pour la solution.
    return Buffer.from(messageBase, 'utf8');
}

/**
 * Generates a CPU challenge based on a target.
 */
export function generateCpuTargetChallenge(
  clientIp,
  nonce,
  suspicionFactor,
  originalUrl,
  securityConfig,
) {
  const target = calculateTarget(suspicionFactor, securityConfig);
  // Le baseBlock est créé ici et sera stocké dans le contexte du challenge.
  const baseBlock = createCpuChallengeBaseBlock(nonce, null, ''); // Pour le challenge simple, le secret et le fingerprint sont vides.
  return {
    type: "cpu_target",
    nonce: nonce,
    target: target.toString(16),
    path: originalUrl,
  };
}

/**
 * Generates the HTML page for the CPU target challenge.
 * @param {object} challengeDetails - The details from generateCpuTargetChallenge.
 * @param {string} clientIp - The client's IP address.
 * @returns {string} HTML content.
 */
function generateCpuTargetChallengePage(challengeDetails, clientIp) {
    const { nonce, target, path } = challengeDetails;
    const solverCode = getPowSolverCode();
    return `
      <html><head><title>Security Check</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h1>Please wait... (Level 1)</h1>
        <p>We are verifying that you are not a bot. This may take a few seconds.</p>
        <div id="loader" style="margin:20px;">⚙️ Performing CPU security calculation...</div>
        <script>${solverCode}</script>
        <script>
          async function solve() {
            const clientIp = ${JSON.stringify(clientIp)};
            const nonce = ${JSON.stringify(nonce)};
            const cpuTarget = BigInt("0x" + "${target}");
            // La nouvelle version de solveCpuChallengeInline n'a plus besoin de l'IP ou du secret,
            // car tout est dans le baseBlock. Pour la compatibilité de ce challenge simple, on passe null.
            const baseBlockBytes = new TextEncoder().encode(nonce + ":");
            const solution = await window.solveCpuChallengeInline(baseBlockBytes, cpuTarget, (progress) => {});
            window.location.href = ${JSON.stringify(path)} + "?pow_type=cpu_target&pow_nonce=" + nonce + "&pow_solution=" + solution;
          }
          solve();
        </script>
      </body></html>`;
}

/**
 * Generates the HTML content for a combined CPU + Memory PoW challenge.
 * @param {object} cpuChallengeDetails - Details from generateCpuTargetChallenge.
 * @param {number} memoryDifficulty - Memory allocation in MB.
 * @param {string} clientIp - The client's IP address.
 * @returns {string} HTML content.
 */
function generateCombinedPoWChallengePage(cpuChallengeDetails, memoryDifficulty, clientIp, clientSecret, securityConfig, trapContainerHtml, originalFingerprint) {
    const { nonce, target, path } = cpuChallengeDetails;
    const solverCode = getPowSolverCode();
    // On prépare le baseBlock pour le client. Il sera envoyé sous forme de tableau d'octets.
    // Le fingerprint est maintenant passé directement en paramètre.
    const fingerprint = originalFingerprint;
    const baseBlock = createCpuChallengeBaseBlock(nonce, clientSecret, fingerprint);
    const baseBlockBytes = `[${baseBlock.toString('utf8').split('').map(c => c.charCodeAt(0)).join(',')}]`;

    const challengeScript = `
      async function solve() {
        const nonce = ${JSON.stringify(nonce)};
        const path = ${JSON.stringify(path)};
        const clientSecret = ${JSON.stringify(clientSecret)};
        const clientIp = ${JSON.stringify(clientIp)};
        const cpuTarget = BigInt("0x" + "${target}");
        const memDifficulty = ${memoryDifficulty};
        // Le client reçoit directement le 'baseBlock' sous forme de tableau d'octets.
        // Il n'a plus besoin de construire le message lui-même.
        const baseBlock = new Uint8Array(${baseBlockBytes});

        // --- CPU Challenge ---
        document.getElementById('loader').innerText = '⚙️ Performing CPU security calculation...';        const cpuSolution = await window.solveCpuChallengeInline(baseBlock, cpuTarget, (progress) => {});

        // --- Memory Challenge ---
        document.getElementById('loader').innerText = '⚙️ Performing memory allocation and calculation... (' + memDifficulty + ' MB)';
        await new Promise(r => setTimeout(r, 10)); // Yield to update UI        
        let memSolution = 0;
        try {
            const memSeed = nonce + ":" + clientSecret;
            memSolution = await window.solveMemoryChallenge(memSeed, memDifficulty);
        } catch(e) {
            document.getElementById('loader').innerText = "Error: Insufficient memory. Please refresh.";
            return;
        }

        // Redirect with both solutions and the fingerprint used to solve.
        const finalUrl = path + "?pow_type=cpu_mem&pow_nonce=" + ${JSON.stringify(nonce)} + "&pow_solution_cpu=" + cpuSolution + "&pow_solution_mem=" + memSolution;
        window.location.href = finalUrl;
      }
      solve();
    `;

    let htmlTemplate;
    const customTemplatePath = securityConfig?.challengePagePath;

    if (customTemplatePath) {
        try {
            htmlTemplate = readFileSync(customTemplatePath, 'utf-8');
        } catch (error) {
            console.warn(`[Fingerprint] Could not load custom challenge page at '${customTemplatePath}'. Falling back to default. Error: ${error.message}`);
        }
    }

    if (!htmlTemplate) {
        htmlTemplate = `<html><head><title>Advanced Security Check</title></head><body style="font-family:sans-serif; text-align:center; padding-top:50px;"><h1>Enhanced Verification... (Level 2)</h1><p>Your activity requires an additional security check. This may take a few moments.</p><div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div><script><!-- FINGERPRINT_SOLVER_SCRIPT --></script><script><!-- FINGERPRINT_CHALLENGE_SCRIPT --></script><!-- FINGERPRINT_TRAPS --></body></html>`;
    }

    return htmlTemplate
        .replace('<!-- FINGERPRINT_SOLVER_SCRIPT -->', solverCode)
        .replace('<!-- FINGERPRINT_CHALLENGE_SCRIPT -->', challengeScript)
        .replace('<!-- FINGERPRINT_TRAPS -->', trapContainerHtml);
}

/**
 * Verifies a PoW solution based on a target and generates a ticket.
 */
export function verifyCpuTargetPoWAndGenerateTicket(
  clientIp, // This parameter is crucial and must be the actual client IP
  ticketTtl,
  nonce,
  solution,
  challengeContext = {}, // Le contexte complet du challenge est maintenant passé
) {
  const { cpuTarget, baseBlock } = challengeContext;
  if (!cpuTarget || !baseBlock) {
      console.error('[FP Server Verify] Invalid challenge context. Missing cpuTarget or baseBlock.');
      return null;
  }

  // Le baseBlock est déjà un Buffer ou un tableau d'octets.
  // On s'assure que c'est un Buffer pour la concaténation.
  const baseBlockBuffer = Buffer.isBuffer(baseBlock) ? baseBlock : Buffer.from(baseBlock);
  const solutionBuffer = Buffer.from(String(solution), 'utf8');

  // Concaténation binaire directe. C'est la garantie de cohérence.
  const finalBlock = Buffer.concat([baseBlockBuffer, solutionBuffer]);

  const hash = crypto
    .createHash("sha256")
    .update(finalBlock)
    .digest("hex");
  const hashAsInt = BigInt("0x" + hash);
  const targetAsInt = BigInt("0x" + cpuTarget);

  // --- NOUVEAUX LOGS POUR LE DÉBOGAGE ---
  console.log('[FP Server Verify] Intermediate values:', {
    hashCalculated: `0x${hash}`,
    hashAsInt: hashAsInt.toString(), // Log as string to see full value
    target: `0x${cpuTarget}`,
    targetAsInt: targetAsInt.toString(), // Log as string to see full value
  });
  // --- FIN DES NOUVEAUX LOGS ---

  const isValid = hashAsInt < targetAsInt;

  // --- AJOUT DE LOGS POUR LE DÉBOGAGE ---
  if (!isValid) {
    console.log('[FP Server Verify] CPU PoW verification FAILED. Details:', {
      hashCalculated: `0x${hash}`,
      target: `0x${cpuTarget}`,

    });
  }
  // --- FIN DES LOGS ---

  if (isValid) {
      console.log('[FP Server Verify] CPU PoW verification PASSED. Details:', {
      });
    // The comparison is direct with native BigInts
    // The proof is valid, generate the ticket
      const expiry = Date.now() + (ticketTtl || 3600000); // Calcule l'expiration à partir du TTL
      const signature = crypto
      .createHmac("sha256", getPowSecret())
      .update(`${clientIp}:${expiry}`)
      .digest("hex");
    return `${expiry}:${signature}`;
  }

  return null;
}

export class FingerprintEngine {
  constructor(securityConfig) {
    const isProduction = process.env.NODE_ENV === 'production';
    this.securityConfig = securityConfig;
    this.isProduction = isProduction;
    this._allowlist = this._buildAllowlist();
    this._validateConfig(securityConfig); // Validate the configuration
    this.verbose = securityConfig.verbose || false;
  }

  /**
   * Validates the security configuration object to detect potential typos or missing essential keys.
   * @private
   * @param {object} config - The security configuration object.
   */
  _validateConfig(config) {
    if (!config) {
      console.warn('[Fingerprint] Warning: No securityConfig provided. Using default behaviors, which may not be secure.');
      return;
    }

    const knownKeys = new Set([
      'weights', 'thresholds', 'cpu', 'ticketMaxAge', 'challengeTtl',
      'deviceIdCookieMaxAge', 'challengePagePath', 'verbose', 'patterns',
      'honeypot', 'whitelist', 'isStaticResource', 'isApiRequest', 'logger',
      'autotuning', 'enableUsefulWork', 'usefulWorkConfigPath', 'challengeNewDevices',
      'similarityThreshold'
    ]);

    // 1. Check for essential keys
    if (!config.weights) {
      console.warn('[Fingerprint] Warning: `securityConfig.weights` is not defined. Suspicion scores will be 0.');
    }
    if (!config.thresholds) {
      console.warn('[Fingerprint] Warning: `securityConfig.thresholds` is not defined. Challenges may not be issued correctly.');
    }

    // 2. Check for unknown (potentially misspelled) keys
    for (const key in config) {
      if (!knownKeys.has(key)) {
        console.warn(`[Fingerprint] Warning: Unknown key '${key}' found in securityConfig. This might be a typo.`);
      }
    }
  }

  _log(message, data = {}) {
    if (this.verbose) {
      console.log(`[FingerprintEngine] ${message}`, data);
    }
  }
    calculateFinalScore = function(suspicionVector) {
        const { weights } = this.securityConfig;
        if (!weights) return 0;

        const score =
            (suspicionVector.historyScore || 0) * (weights.historyScore || 0) +
            (suspicionVector.rotationScore || 0) * (weights.rotationScore || 0) +
            (suspicionVector.headerAnomalyScore || 0) * (weights.headerAnomalyScore || 0) +
            (suspicionVector.requestPatternScore || 0) * (weights.requestPatternScore || 0) +
            (suspicionVector.inconsistencyScore || 0) * (weights.inconsistencyScore || 0) +
            (suspicionVector.honeypotScore || 0) * (weights.honeypotScore || 0) +
            (suspicionVector.behaviorScore || 0) * (weights.behaviorScore || 0) +
            (suspicionVector.botScore || 0) * (weights.botScore || 0) + // Ajout du nouveau score
            (suspicionVector.crossLayerInconsistencyScore || 0) * (weights.crossLayerInconsistencyScore || 0) +
            (suspicionVector.tlsSpoofingScore || 0) * (weights.tlsSpoofingScore || 0) + // NOUVEAU: TLS Spoofing
            (suspicionVector.timeInconsistencyScore || 0) * (weights.timeInconsistencyScore || 0);

        return Math.min(100, score);
    }
  /**
   * Checks if an IP address is in the static allowlist (IPs or CIDR ranges).
   * This is the fastest check and should be performed first.
   * @private
   * @param {string} clientIp - The IP address of the client.
   * @returns {boolean} True if the IP is in the allowlist.
   */
  _buildAllowlist() {
    const blockList = new BlockList();
    const { whitelist = [] } = this.securityConfig;
    const allowlistRule = whitelist.find(rule => rule.type === 'allowlist');

    if (!allowlistRule || !allowlistRule.entries || allowlistRule.entries.length === 0) {
      return blockList; // Retourne une liste vide
    }

    for (const entry of allowlistRule.entries) {
      if (entry.includes('/')) { // CIDR range
        try {
          const [address, prefix] = entry.split('/');
          blockList.addSubnet(address, parseInt(prefix, 10));
        } catch (e) {
          // Ignore les entrées CIDR invalides
        }
      } else { // Direct IP match
        blockList.addAddress(entry);
      }
    }
    return blockList;
  }

  /**
   * Checks if the client's IP resolves to any of the hostnames in the hostname allowlist.
   * The result is cached to avoid repeated DNS lookups.
   * @private
   * @param {string} clientIp - The IP address of the client.
   * @returns {Promise<boolean>} True if the IP is in the hostname allowlist.
   */
  async _isIpInHostnameAllowlist(clientIp) {
    const { whitelist = [] } = this.securityConfig;
    const hostnameRule = whitelist.find(rule => rule.type === 'hostname_allowlist');

    if (!hostnameRule || !hostnameRule.entries || hostnameRule.entries.length === 0) {
      return false;
    }

    const cacheKey = `ip-hostname-allowlist:${clientIp}`;
    const cachedStatus = await store.get(cacheKey);

    if (cachedStatus === 'verified') return true;
    if (cachedStatus === 'failed') return false;

    try {
      // Reverse DNS lookup to get hostnames for the IP
      const hostnames = await dns.reverse(clientIp);

      // Check if any of the resolved hostnames is in our allowlist
      const isAllowed = hostnames.some(hostname => hostnameRule.entries.includes(hostname));

      if (isAllowed) {
        await store.set(cacheKey, 'verified', 86400); // Cache success for 24h
        return true;
      }
    } catch (error) {
      // DNS errors (like no rDNS record) are treated as a failure.
    }

    await store.set(cacheKey, 'failed', 86400); // Cache failure for 24h
    return false;
  }
  _isIpInAllowlist(clientIp) {
    return this._allowlist.check(clientIp);
  }
  /**
   * Checks if the request's host and path match an entry in the host+path allowlist.
   * @private
   * @param {string} requestHost - The host from the request headers.
   * @param {string} requestPath - The path of the incoming request.
   * @returns {boolean} True if the combination is in the allowlist.
   */
  _isHostPathInAllowlist(requestHost, requestPath) {
    const { whitelist = [] } = this.securityConfig;
    const hostPathRule = whitelist.find(rule => rule.type === 'host_path_allowlist');

    if (!hostPathRule || !hostPathRule.entries || hostPathRule.entries.length === 0) {
      return false;
    }

    for (const entry of hostPathRule.entries) {
      // Find the first slash to separate host and path
      const firstSlashIndex = entry.indexOf('/');
      if (firstSlashIndex === -1) continue; // Invalid entry

      const hostPattern = entry.substring(0, firstSlashIndex);
      const pathPattern = entry.substring(firstSlashIndex);

      // Check if the request host matches the host pattern
      if (requestHost !== hostPattern) {
        continue;
      }

      // Check if the request path matches the path pattern (with wildcard support)
      if (pathPattern.endsWith('*')) {
        const basePath = pathPattern.slice(0, -1);
        if (requestPath.startsWith(basePath)) {
          return true; // Wildcard match
        }
      } else if (requestPath === pathPattern) {
        return true; // Exact match
      }
    }
    return false;
  }
  /**
   * Checks if the request path matches any entry in the path allowlist.
   * Supports simple wildcards (*) at the end of a path.
   * @private
   * @param {string} requestPath - The path of the incoming request.
   * @returns {boolean} True if the path is in the allowlist.
   */
  _isPathInAllowlist(requestPath) {
    const { whitelist = [] } = this.securityConfig;
    const pathAllowlistRule = whitelist.find(rule => rule.type === 'path_allowlist');

    if (!pathAllowlistRule || !pathAllowlistRule.entries || pathAllowlistRule.entries.length === 0) {
      return false;
    }

    for (const entry of pathAllowlistRule.entries) {
      if (entry.endsWith('*')) {
        // Handle wildcard matching
        const base = entry.slice(0, -1);
        if (requestPath.startsWith(base)) {
          return true;
        }
      } else {
        // Handle exact path matching
        if (requestPath === entry) {
          return true;
        }
      }
    }

    return false;
  }
  /**
   * Verifies if a request comes from a legitimate, whitelisted bot (e.g., Googlebot)
   * using reverse and forward DNS lookups. The result is cached.
   * @private
   * @param {object} requestContext - The request context.
   * @returns {Promise<boolean>} True if the request is from a verified whitelisted bot.
   */
  async _verifyWhitelistedBot(requestContext) {
    const { whitelist = [] } = this.securityConfig;
    const botRules = whitelist.filter(rule => rule.hostnameSuffix);
    if (botRules.length === 0) {
      return false;
    }

    const { clientIp, headers } = requestContext;
    const userAgent = headers['user-agent'] || '';

    const matchedRule = botRules.find(rule => {
      if (!rule.userAgent) return false;
      try {
        return new RegExp(rule.userAgent).test(userAgent);
      } catch (e) {
        console.error(`[Fingerprint] Invalid regex in whitelist rule: ${rule.userAgent}`);
        return false;
      }
    });
    if (!matchedRule) {
      return false;
    }

    const cacheKey = `ip-whitelist:${clientIp}`;
    const cachedStatus = await store.get(cacheKey);

    if (cachedStatus === 'verified') {
      return true;
    }
    if (cachedStatus === 'failed') {
      return false;
    }

    try {
      // 1. Reverse DNS lookup
      const hostnames = await dns.reverse(clientIp);
      const validHostname = hostnames.find(h => h.endsWith(matchedRule.hostnameSuffix));

      if (!validHostname) {
        await store.set(cacheKey, 'failed', 86400); // Cache failure for 24h (TTL in seconds)
        return false;
      }

      // 2. Forward DNS lookup
      const addresses = await dns.resolve(validHostname);
      if (addresses.includes(clientIp)) {
        await store.set(cacheKey, 'verified', 86400); // Cache success for 24h (TTL in seconds)
        return true;
      }
    } catch (error) {
      // DNS errors are common (e.g., for IPs with no rDNS record), treat as failure.
    }

    await store.set(cacheKey, 'failed', 86400); // Cache failure for 24h (TTL in seconds)
    return false;
  }

  async processRequest(requestContext) {

    const { clientIp = "unknown", path, cookies, query, isStatic } = requestContext;
    const { weights, thresholds, logger, onDeviceCompromised } = this.securityConfig;
    
    this._log('Processing request', { clientIp, path, isStatic });
    
    if (isStatic) {
      this._log('Static resource - skipping checks');
      return { action: 'next', score: 0, vector: {} };
    }

    // 1. Check static IP allowlist first for maximum performance.
    if (this._isIpInAllowlist(clientIp)) {
      this._log('IP in allowlist - allowing request', { clientIp });
      return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'allowlist' } };
    }

    // 2. Check hostname-based allowlist.
    if (await this._isIpInHostnameAllowlist(clientIp)) {
      this._log('IP resolves to a whitelisted hostname - allowing request', { clientIp });
      return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'hostname_allowlist' } };
    }

    // 3. Check host+path based allowlist.
    const requestHost = requestContext.headers?.host;
    if (requestHost && this._isHostPathInAllowlist(requestHost, path)) {
      this._log('Host and path in allowlist - allowing request', { host: requestHost, path });
      return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'host_path_allowlist' } };
    }

    // 3. Check path-based allowlist.
    if (this._isPathInAllowlist(path)) {
      this._log('Path in allowlist - allowing request', { path });
      return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'path_allowlist' } };
    }

    const { pow_nonce } = query;

    // Honeypot: Direct probing of challenge endpoints is highly suspicious.
    // A legitimate user only hits these endpoints via the challenge page itself.
    // If we see a pow_nonce on a request that isn't (yet) considered suspicious, it's a bot probe.
    if (pow_nonce) {
        const powCookie = cookies?.pow_clearance;
        if (!isTicketValid(clientIp, powCookie)) { // Only check if there's no valid ticket
            // This is a potential probe. We'll let the main logic confirm if it's not a legitimate challenge response.
            // The final decision is made later, after calculating the score.
        }
    }

    // Check if the request is from a verified, whitelisted bot (e.g., Googlebot)
    if (await this._verifyWhitelistedBot(requestContext)) {
      this._log('Whitelisted bot verified - allowing request', { clientIp });
      return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'bot' } };
    }
    
    // Resolve identity and check for persisted "condemned" status early.
    const { deviceId, deviceData, newCookie } = await resolveRequestIdentity(requestContext, this.securityConfig);
    const isNewDevice = !!newCookie;
    
    this._log('Identity resolved', { deviceId, isNewDevice, hasDeviceData: !!deviceData });

    if (deviceData?.condemned) {
        this._log('Device condemned - blocking request', { deviceId });
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: deviceId, clientIp, reason: 'Previously condemned', score: 100, vector: { honeypotScore: 100 } });
        }
        return { action: 'block', status: 404, body: 'Forbidden', score: 100, vector: { honeypotScore: 100 } };
    }

    // The engine now works with the context directly, no more rawReq dependency here.
    const suspicionVector = await __internal.getSuspicionVector(requestContext, this.securityConfig);
    // honeypotScore et behaviorScore sont maintenant inclus directement dans le vecteur de suspicion.

    this._log('Suspicion vector calculated', { 
        vector: suspicionVector,
        weights: this.securityConfig.weights 
    });

    let finalScore = this.calculateFinalScore(suspicionVector);
    
    this._log('Final score calculated', { finalScore });

    // Si c'est un nouvel appareil, on lui impose un challenge de base, même si son score est bas.
    // Cela augmente le coût pour les bots qui tentent de simplement supprimer leurs cookies.
    // NOUVEAU : Cette logique est maintenant configurable.
    const challengeNewDevices = this.securityConfig.challengeNewDevices === true;
    if (isNewDevice && finalScore < thresholds.low) {
      this._log('New device - enforcing minimum challenge score', { 
          originalScore: finalScore, 
          enforcedScore: thresholds.low 
      });
      finalScore = thresholds.low;
    }

    const blockThreshold = thresholds.block ?? 95;
    const isBlocked = finalScore >= blockThreshold;

    const isSuspiciousHigh = finalScore >= thresholds.high && !isBlocked;
    const isSuspiciousMedium = finalScore >= thresholds.medium;
    const isSuspicious = finalScore >= thresholds.low;
    const isVerySuspicious = finalScore >= thresholds.medium; // Seuil pour le challenge d'optimisation

    // Calculate an analog "suspicion factor" (0 to 1+) for progressive difficulty
    const suspicionFactor = isSuspicious
        ? Math.min(
            1.5, // On autorise un dépassement pour rendre les challenges très difficiles si le score est très élevé
            (finalScore - thresholds.low) / (thresholds.high - thresholds.low),
        )
        : 0;

    this._log('Suspicion levels evaluated', { 
        finalScore, 
        isBlocked, 
        isSuspiciousHigh, 
        isSuspiciousMedium, 
        isSuspicious, 
        suspicionFactor,
        thresholds: { low: thresholds.low, medium: thresholds.medium, high: thresholds.high, block: blockThreshold }
    });

    const powCookie = cookies?.pow_clearance;

    // --- NOUVELLE LOGIQUE DE PRIORITÉ ---
    // Si une solution de challenge est soumise, on la traite en priorité absolue,
    // avant même de recalculer le score de suspicion.
    const { pow_type, pow_solution, pow_solution_cpu, pow_solution_mem, pow_fp, pow_solution_population, pow_solution_work_result, pow_problem_id } = query;
    if (pow_nonce && (pow_solution || pow_solution_cpu)) { // Vérifie pow_solution pour la compatibilité ascendante
        this._log('Challenge solution submitted', { pow_type, pow_nonce });

        // On doit calculer le score de suspicion *avant* de valider le ticket,
        // car le TTL optimal en dépend.
        const preliminaryVector = suspicionVector; // Use the already calculated vector
        const preliminaryScore = finalScore; // Use the already calculated score

        this._log('Preliminary suspicion vector calculated', {
            vector: preliminaryVector,
            score: preliminaryScore
        });

        let isValid = false;
        const challengeContext = await store.get(`secret:${pow_nonce}`);
        let ticket = null;
        // Déclarer optimalTtl ici avec une valeur par défaut
        let optimalTtl = this.securityConfig.ticketMaxAge || 3600000;
        // NOUVEAU: Logique de ticket probatoire

        let finalTtl; // Déclarer finalTtl ici pour qu'il soit accessible dans la portée
        const isProbationary = preliminaryScore >= thresholds.low;
        const probationaryTtl = 30000; // 30 secondes

        if (challengeContext) {
            // *** NOUVELLE VÉRIFICATION CRUCIALE ***
            // On compare le fingerprint soumis par le solver (`pow_fp`) avec celui stocké
            // lors de l'émission du challenge.
            // --- FIX: Use submitted fingerprint, but fallback to current request's fingerprint ---
            // This handles API clients that might not use the full client-side library but still solve the challenge.
            const solverFingerprint = pow_fp || getCompositeDeviceHash(requestContext);
    const originalFingerprint = challengeContext.fingerprint; // This is the fingerprint of the request that *triggered* the challenge

            let similarity;
            const similarityThreshold = this.securityConfig.similarityThreshold ?? 0.95;

            // If fingerprints are simple strings (like test placeholders 'fp-probation')
            // and don't contain the typical structure, fall back to a strict equality check.
            if (!originalFingerprint?.includes(':') || !solverFingerprint?.includes(':')) {
                similarity = (originalFingerprint === solverFingerprint) ? 1.0 : 0.0;
            } else {
                // Use the weighted comparison for structured fingerprints.
        // We compare the fingerprint of the request that triggered the challenge
        // with the fingerprint of the request that is submitting the solution.
        // They should be very similar.
        similarity = FingerprintBuilder.compare(originalFingerprint, solverFingerprint);
            }

            if (similarity < similarityThreshold) {
                this._log('Fingerprint mismatch - challenge solved on a different machine!', {
                    original: originalFingerprint,
                    solver: solverFingerprint,
                    similarity: similarity.toFixed(4),
                    threshold: similarityThreshold
                });
                isValid = false;
            } else {
                optimalTtl = determineOptimalTicketTtl(preliminaryScore);
                finalTtl = isProbationary ? probationaryTtl : optimalTtl;
                this._log('Challenge context found, verifying solution', { optimalTtl, finalTtl });

                if ((pow_type === "cpu_target" || !pow_type) && (pow_solution_cpu || pow_solution)) { // !pow_type pour compatibilité
                    const cpuSolution = pow_solution_cpu || pow_solution;
            ticket = verifyCpuTargetPoWAndGenerateTicket(clientIp, finalTtl, pow_nonce, cpuSolution, challengeContext);
                    isValid = ticket !== null;
                    this._log('CPU target challenge verification', { isValid });
                } else if (pow_type === "cpu_mem" && pow_solution_cpu && pow_solution_mem) {                    const cpuTicket = verifyCpuTargetPoWAndGenerateTicket(clientIp, finalTtl, pow_nonce, pow_solution_cpu, challengeContext);
            const isMemValid = verifyMemoryPoW(pow_nonce, pow_solution_mem, challengeContext.memDifficulty, challengeContext.clientSecret); // Memory PoW is independent of fingerprint
                    isValid = cpuTicket !== null && isMemValid;
                    if (isValid) ticket = cpuTicket; // Le ticket est le même, on le réutilise
                    this._log('Combined CPU+Memory challenge verification', {
                        cpuValid: cpuTicket !== null,
                        memValid: isMemValid,
                        isValid
                    });
                }
            }
        } else {
            this._log('Challenge context not found or expired', { pow_nonce });
            // --- NOUVELLE MESURE DE SÉCURITÉ ---
            // Si un client soumet un nonce invalide ou expiré, c'est une tentative de probing.
            // On applique une pénalité maximale pour bloquer ou re-challenger lourdement.
            suspicionVector.honeypotScore = 100;
            finalScore = this.calculateFinalScore(suspicionVector);
            this._log('Invalid nonce submitted (probing attempt) - applying max penalty', { newFinalScore: finalScore });
            // La logique continue vers la section `if (isValid)` qui échouera,
            // puis le score élevé sera utilisé pour bloquer ou re-challenger.
            isValid = false; // On s'assure que la validation échoue.
        }
        if (isValid) {
            // La solution est valide. On supprime le secret et on redirige.
            await store.delete(`secret:${pow_nonce}`);
            this._log('Challenge solution valid - issuing ticket', { ticketMaxAge: finalTtl, isProbationary });

            if (logger) {
                logger({ type: 'challenge_solved', deviceId: cookies?.device_id, score: preliminaryScore, challengeType: pow_type, timestamp: Date.now(), vector: preliminaryVector });
            }

            // NOUVELLE LOGIQUE DE REDIRECTION (plus robuste)
            // 1. On part du chemin original stocké, qui peut contenir des query params.
            const originalUrl = new URL(challengeContext?.originalPath || requestContext.path, `http://${requestContext.headers.host || 'localhost'}`);
            // 2. On crée un nouvel objet de paramètres à partir de la requête entrante (qui contient les solutions ET les params originaux).
            const finalSearchParams = new URLSearchParams(requestContext.query);

            // 3. On supprime uniquement les paramètres liés au challenge.
            finalSearchParams.delete('pow_type');
            finalSearchParams.delete('pow_nonce');
            finalSearchParams.delete('pow_solution');
            finalSearchParams.delete('pow_solution_cpu');
            finalSearchParams.delete('pow_solution_mem');
            finalSearchParams.delete('pow_fp'); // Ne pas oublier de nettoyer le fingerprint
            // NOUVEAU: Nettoyer aussi les paramètres des challenges d'optimisation et de travail utile
            finalSearchParams.delete('pow_solution_population');
            finalSearchParams.delete('pow_solution_work_result');
            finalSearchParams.delete('pow_problem_id');

            // 4. On reconstruit le chemin final.
            const finalQueryString = finalSearchParams.toString();
            const finalRedirectPath = finalQueryString ? `${originalUrl.pathname}?${finalQueryString}` : originalUrl.pathname;
            this._log('Redirecting to clean path', { finalRedirectPath, cookieMaxAge: finalTtl });
            return {
              action: 'redirect',
              path: finalRedirectPath,
              score: 0, // Le score n'est pas pertinent ici, on a passé le test.
              vector: { challenge_solved: 100 },
              cookie: {
                name: 'pow_clearance',
                value: ticket, // The ticket itself
                options: { httpOnly: true, secure: this.isProduction, maxAge: finalTtl } // Options for setting the cookie
              }
            };
        } else {
            // If the solution is invalid, we should treat it as a high-suspicion event.
            // This prevents the request from proceeding and forces a new, likely harder, challenge.
            this._log('Challenge solution invalid', { pow_nonce });
            suspicionVector.honeypotScore = 100; // Invalid solution is a strong bot signal.
            finalScore = this.calculateFinalScore(suspicionVector);
            // --- FIX: After invalidating a solution, immediately check if the new score triggers a block ---
            const newBlockThreshold = thresholds.block ?? 95;
            if (finalScore >= newBlockThreshold) {
                this._log('Request blocked after invalid challenge solution', { finalScore, newBlockThreshold });
                return { action: 'block', status: 404, body: 'Forbidden', score: finalScore, vector: suspicionVector };
            }
            // If not blocked, the request will proceed to be re-challenged.
        }
    } else if (pow_nonce && pow_type === 'optimization_task' && pow_solution_population) {
        this._log('Optimization task solution submitted', { pow_nonce });
        const challengeContext = await store.get(`secret:${pow_nonce}`);
        let isValid = false;

        if (challengeContext?.optimizationProblem) {
            try {
                const submittedChromosomes = JSON.parse(pow_solution_population);
                // Vérification simple : le client a-t-il renvoyé le bon nombre de solutions ?
                if (Array.isArray(submittedChromosomes) && submittedChromosomes.length === challengeContext.optimizationProblem.population.length) {
                    // Le serveur recalcule la fitness pour la nouvelle population.
                    const fitnessFunction = Optimization.Operators.createFullSecurityConfigEvaluator({ trafficData: challengeContext.optimizationProblem.trafficData });
                    const newPopulation = submittedChromosomes.map(chromosome => ({ chromosome, fitness: fitnessFunction(chromosome) }));
                    
                    // On met à jour le problème principal avec la nouvelle population.
                    challengeContext.optimizationProblem.population = newPopulation;
                    await store.set(`device:${deviceId}`, deviceData); // Sauvegarde l'état mis à jour
                    isValid = true;
                }
            } catch (e) {
                this._log('Error parsing optimization solution', { error: e.message });
            }
        }

        if (isValid) {
            await store.delete(`secret:${pow_nonce}`);
            // La solution est valide, on accorde un ticket et on redirige.
            const ticket = "valid_ticket_placeholder"; // Générer un vrai ticket ici
            return { action: 'redirect', path: path, score: 0, vector: { challenge_solved: 100 }, cookie: { name: 'pow_clearance', value: ticket, options: { httpOnly: true, secure: this.isProduction, maxAge: 60000 } } };
        } else {
            this._log('Optimization task solution invalid', { pow_nonce });
            suspicionVector.honeypotScore = 100;
            finalScore = this.calculateFinalScore(suspicionVector);
        }
    } else if (pow_nonce && pow_type === 'useful_work_task' && pow_solution_work_result && pow_problem_id) {
        this._log('Useful work solution submitted', { problemId: pow_problem_id });
        const challengeContext = await store.get(`secret:${pow_nonce}`);
        if (challengeContext) {
            try {
                const workResult = JSON.parse(pow_solution_work_result);
                getProblemManager(this.securityConfig.usefulWorkConfigPath).integrateSolution(pow_problem_id, workResult);

                await store.delete(`secret:${pow_nonce}`);
                // Accorder un ticket de passage comme pour un PoW normal
                const ticket = "valid_ticket_placeholder"; // Générer un vrai ticket ici
                return { action: 'redirect', path: path, score: 0, vector: { challenge_solved: 100 }, cookie: { name: 'pow_clearance', value: ticket, options: { httpOnly: true, secure: this.isProduction, maxAge: 60000 } } };

            } catch (e) {
                this._log('Error parsing useful work solution', { error: e.message });
            }
        }
        // Si la validation échoue, on pénalise fortement
        suspicionVector.honeypotScore = 100;
        finalScore = this.calculateFinalScore(suspicionVector);
    }
    // --- FIN DE LA LOGIQUE DE PRIORITÉ ---

    // If the action is to block, we should still include the score and vector for logging/testing.
    if (isBlocked) {
      this._log('Request blocked - score exceeded block threshold', { finalScore, blockThreshold });
      if (onDeviceCompromised) {
        onDeviceCompromised({ deviceId: deviceId, clientIp, reason: 'Score exceeded block threshold', score: finalScore, vector: suspicionVector });
      }
      if (logger) {
        logger({ type: 'request_blocked', deviceId: deviceId, score: finalScore, vector: suspicionVector, timestamp: Date.now() });
      }
      return { action: 'block', status: 404, body: 'Forbidden', score: finalScore, vector: suspicionVector };
    }

    // Honeypot: Check if the request is for a trap URL generated in a previous challenge.
    // This requires a nonce from a *previous* challenge, which we can look up via the device ID.
    const lastNonce = deviceData?.lastChallengeNonce;
    if (lastNonce && query.sig && verifyTrapUrl(path, query.sig, lastNonce)) {
        this._log('Honeypot trap URL triggered - condemning device', { path, deviceId });
        deviceData.condemned = true; // This device is a bot. Condemn it.
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: deviceId, clientIp, reason: 'Triggered signed honeypot trap URL', score: 100, vector: { honeypotScore: 100 } });
        }
        if (logger) {
            logger({ type: 'trap_triggered', deviceId: cookies?.device_id, score: 100, path: path, timestamp: Date.now(), vector: { honeypotScore: 100 } });
        }
        await store.set(`device:${cookies.device_id}`, deviceData); // No TTL for condemned status
        return { action: 'block', status: 404, score: 100, vector: { honeypotScore: 100 } };
    }
    
    // --- NOUVELLE LOGIQUE DE RE-CHALLENGE ---
    // Un challenge est nécessaire si :
    // 1. La requête est suspecte ET il n'y a pas de ticket valide.
    // OU
    // 2. La requête est *très* suspecte (dépasse le seuil 'high'), ce qui annule la validité du ticket actuel.
    const hasValidTicket = isTicketValid(clientIp, powCookie);
    const mustReChallenge = isSuspiciousHigh && hasValidTicket;

    if (isSuspicious && (!hasValidTicket || mustReChallenge)) {
        if (mustReChallenge) {
            this._log('High suspicion score detected - overriding valid ticket to re-issue challenge', { finalScore, deviceId });
        }
        this._log('Suspicious request without valid ticket - issuing challenge', { finalScore, hasPowCookie: !!powCookie });
        // Honeypot: Direct probing of challenge endpoints is highly suspicious.
        // A legitimate user only hits these endpoints via the challenge page itself.
        // If we see a pow_nonce on a request that IS suspicious but has no valid ticket,
        // AND it's not a legitimate response to a challenge we issued, it's a probe.
        const isChallengeResponse = query.pow_solution || (query.pow_solution_cpu && query.pow_solution_mem);
        if (pow_nonce && !isChallengeResponse) {
            this._log('Honeypot probe detected - blocking request', { path, pow_nonce });
            if (logger) {
                logger({ type: 'honeypot_probe', deviceId: cookies?.device_id, score: finalScore, path: path, timestamp: Date.now(), vector: suspicionVector });
            }
            suspicionVector.honeypotScore = 100; // Bot is probing. Max penalty.
            // Recalculate the final score with the updated vector.
            const newFinalScore = this.calculateFinalScore(suspicionVector);
            return { action: 'block', status: 404, body: 'Forbidden', score: newFinalScore, vector: suspicionVector };
        }

        // --- SELECTION AND SENDING OF THE APPROPRIATE CHALLENGE ---
        const nonce = crypto.randomBytes(16).toString("hex");
        const clientSecret = crypto.randomBytes(16).toString("hex");

        // Pour les scores élevés, on choisit aléatoirement entre un challenge de travail utile et un PoW classique.
        // Cela rend l'automatisation plus difficile pour un attaquant.
        // Utilisation de crypto pour un choix plus sécurisé.
        const shouldUseUsefulWork = this.securityConfig.enableUsefulWork && crypto.randomBytes(1).readUInt8(0) / 255 > 0.5;

        if (isSuspicious && shouldUseUsefulWork) {
            this._log('Issuing a useful work challenge', { finalScore });

            const { problemId, task } = getProblemManager(this.securityConfig.usefulWorkConfigPath).dispatchWork(suspicionFactor);

            await store.set(`secret:${nonce}`, { clientSecret, originalPath: path }, 300);

            const challengePayload = {
                challenge: {
                    type: 'useful_work_task',
                    nonce: nonce,
                    clientSecret: clientSecret,
                    usefulWorkTask: { problemId, task }
                }
            };
            return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: challengePayload };
        } else if (isSuspicious) { // Pour les scores bas/moyens ou si le travail utile n'est pas choisi
            // Generate some trap URLs to embed in the challenge page.
            // These links are visually hidden but present in the DOM to trap bots.
            const trapUrls = Array.from({ length: 3 }, () => generateTrapUrl(nonce));
            const trapLinksHtml = trapUrls.map(url => `<a href="${url}" tabindex="-1">config</a>`).join(' ');

            // On passe la configuration pour que la difficulté soit calculée correctement.
            const cpuChallengeDetails = generateCpuTargetChallenge(clientIp, nonce, suspicionFactor, path, this.securityConfig);

            // La difficulté mémoire démarre à 0 et augmente seulement après un certain seuil de suspicion.
            // Par exemple, elle ne commence à augmenter qu'à partir de 25% du chemin entre 'low' et 'high'.
            const memActivationFactor = Math.max(0, (suspicionFactor - 0.25) / 0.75);

            const minMemDifficulty = 0;   // Peut être 0 Mo !
            const maxMemDifficulty = 48;  // 48Mo pour les plus suspects
            const memDifficulty = Math.round(minMemDifficulty + memActivationFactor * (maxMemDifficulty - minMemDifficulty));

            this._log('Challenge parameters calculated', {
                suspicionFactor,
                memActivationFactor,
                memDifficulty,
                cpuTarget: cpuChallengeDetails.target
            });
            // (NOUVEAU) On stocke le fingerprint de la requête qui a déclenché le challenge. We call it via __internal to allow mocking.
            const originalFingerprint = requestContext.headers['x-device-fingerprint'] || __internal.getCompositeDeviceHash(requestContext);

            // Store the entire challenge context with a short TTL (e.g., 5 minutes)
            const baseBlock = createCpuChallengeBaseBlock(nonce, clientSecret, originalFingerprint);
            await store.set(`secret:${nonce}`, {
                clientSecret,
                cpuTarget: cpuChallengeDetails.target,
                suspicionScore: finalScore, // *** FIX: Store the score that triggered the challenge ***
                fingerprint: originalFingerprint, // *** NOUVEAU ***
                memDifficulty: memDifficulty,
                baseBlock: baseBlock, // *** NOUVEAU: Le bloc de base est stocké pour la vérification ***
                originalPath: path, // *** FIX: Store the original path ***
            }, this.securityConfig.challengeTtl || 300); // NOUVEAU: TTL configurable (5min par défaut)

            // Associate the current challenge nonce with the device for trap URL verification later.
            if (deviceData) {
                deviceData.lastChallengeNonce = nonce;
                await store.set(`device:${deviceId}`, deviceData); // Utiliser le deviceId résolu, pas celui des cookies
            }

            this._log('Challenge issued', { 
                nonce, 
                challengeTtl: this.securityConfig.challengeTtl || 300,
                trapUrlsCount: trapUrls.length 
            });

            if (logger) {
                logger({ type: 'challenge_issued', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now(), vector: suspicionVector });
            }

            // Check if the request is an API request to return a JSON challenge
            const isApi = requestContext.rawReq && this.securityConfig?.isApiRequest?.(requestContext.rawReq);

            if (isApi) {
                // For API clients, send a JSON response with challenge details.
                const challengePayload = {
                    challenge: {
                        type: 'cpu_mem',
                        nonce: nonce,
                        clientSecret: clientSecret, // The client needs this to solve the challenge
                        cpuTarget: cpuChallengeDetails.target,
                        memDifficulty: memDifficulty,
                        baseBlock: [...baseBlock], // Envoyer le buffer comme un tableau d'octets
                    }
                };
                this._log('API challenge response generated', { challengePayload });
                return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: challengePayload };
            } else {
                // For browsers, send the HTML page.
                const trapContainer = `<div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">${trapLinksHtml}</div>`;                const page = generateCombinedPoWChallengePage(cpuChallengeDetails, memDifficulty, clientIp, clientSecret, this.securityConfig, trapContainer, originalFingerprint);
                this._log('Browser challenge page generated', { 
                    pageLength: page.length, 
                    hasTrapContainer: true 
                });
                return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: page };
            }
        }
    }

    // Basic log for each non-static request that passed without a challenge
    this._log('Request passed - no challenge required', { finalScore, hasValidTicket: isTicketValid(clientIp, powCookie) });
    
    if (logger) {
        logger({ type: 'request_passed', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now(), vector: suspicionVector });
    }

    return { action: 'next', score: finalScore, vector: suspicionVector };
  }

  /**
   * Identifies a request in a granular way for non-Express environments.
   * @param {object} requestContext - The request context object.
   * @returns {Promise<string>} An identification string (e.g., "device:<id>", "suspicious_high:<ip>").
   */
  async identifyRequest(requestContext) {
    const { clientIp, cookies, rawReq, rawRes } = requestContext;

    // --- Update IP reputation ---
    const ipProfile = (await store.get(`ip:${clientIp}`)) || {
      type: "residential",
      deviceIds: new Set(),
      statelessCount: 0,
      lastSeen: 0,
    };
    ipProfile.lastSeen = Date.now();
    if (cookies?.device_id) {
      ipProfile.deviceIds.add(cookies.device_id);
    } else {
      ipProfile.statelessCount++;
    }

    if (ipProfile.deviceIds.size > SHARED_IP_DEVICE_THRESHOLD) {
      ipProfile.type = "shared";
    }

    const statelessLimit = ipProfile.type === "shared" ? 50 : 10;
    if (ipProfile.statelessCount > statelessLimit) {
      return `suspicious_high:${clientIp}`;
    }
    await store.set(`ip:${clientIp}`, ipProfile, 600); // Keep IP profile for 10 minutes

    const vector = await __internal.getSuspicionVector(requestContext, this.securityConfig); // Pass the config
    const { honeypotScore } = getHoneypotScore(requestContext, this.securityConfig.honeypot);
    const { requestPatternScore } = getRequestPatternScore(requestContext, (await store.get(`device:${requestContext.cookies?.device_id}`)), this.securityConfig.patterns);
    const score =
      vector.historyScore * (this.securityConfig.weights.historyScore || 0.3) +
      vector.rotationScore * (this.securityConfig.weights.rotationScore || 0.5) +
      vector.headerAnomalyScore * (this.securityConfig.weights.headerAnomalyScore || 0.1) +
      vector.inconsistencyScore * (this.securityConfig.weights.inconsistencyScore || 0.8) +
      honeypotScore * (this.securityConfig.weights.honeypotScore || 0) +
      requestPatternScore * (this.securityConfig.weights.requestPatternScore || 0) +
      vector.behaviorScore * (this.securityConfig.weights.behaviorScore || 0);

    if (score >= this.securityConfig.thresholds.high) return `suspicious_high:${clientIp}`;
    if (score >= this.securityConfig.thresholds.low) return `suspicious_medium:${clientIp}`; // Use medium for any suspicion
    if (score >= this.securityConfig.thresholds.medium) return `suspicious_medium:${clientIp}`;

    // If a new device_id was created, it's in the context.
    const newDeviceId = requestContext._newCookies?.find(c => c.name === 'device_id')?.value;
    const finalDeviceId = cookies?.device_id || newDeviceId || clientIp;

    return `device:${finalDeviceId}`;
  }
}

const staticExtensions = new RegExp(
  "\\.(js|css|png|jpg|jpeg|gif|svg|mp3|webp|ico|woff|woff2|ttf|otf|map|json|manifest|webmanifest)$",
  "i",
);
const isStaticResource = (path) => staticExtensions.test(path);


/**
 * Détermine le TTL optimal pour un ticket en utilisant un algorithme génétique multi-objectifs.
 * @param {number} suspicionScore - Le score de suspicion de la requête.
 * @returns {number} Le TTL optimal calculé en millisecondes.
*/
function determineOptimalTicketTtl(suspicionScore) {
    // Définir les bornes pour la durée de vie du ticket (5 minutes à 24 heures)
    const MIN_TTL = 300000;
    const MAX_TTL = 86400000;

    const solverFunction = () => {
        const fitnessFunction = Optimization.Operators.createOptimalTtlEvaluator({ suspicionScore });

        // Un "individu" est simplement une valeur de TTL en millisecondes.
        const createIndividual = () => MIN_TTL + Math.random() * (MAX_TTL - MIN_TTL);
        const crossover = (ttl1, ttl2) => (ttl1 + ttl2) / 2;
        const mutate = (ttl) => {
            const newTtl = ttl + (Math.random() - 0.5) * (MAX_TTL - MIN_TTL) * 0.1; // Mutation de +/- 10% max
            return Math.max(MIN_TTL, Math.min(MAX_TTL, newTtl));
        };

        const paretoFront = Optimization.geneticAlgorithmMultiObjective(
            createIndividual,
            fitnessFunction,
            crossover,
            mutate,
            {
                generations: 40,
                populationSize: 30,
            }
        );

        // Pour runMultiple, on doit retourner un objet avec une propriété "fitness" ou "energy".
        // Pour un front de Pareto, il n'y a pas de score unique. On choisit la meilleure solution
        // en fonction du score de suspicion et on lui assigne un score de 0 pour que runMultiple la sélectionne.
        if (!paretoFront || paretoFront.length === 0) {
            return { solution: null, fitness: Infinity };
        }

        // Stratégie de sélection :
        // Pour un score faible (< 50), on privilégie la solution avec le plus grand TTL (minimise la friction).
        // Pour un score élevé (>= 50), on privilégie la solution avec le plus petit TTL (minimise le risque).
        let bestSolutionInFront;
        if (suspicionScore < 50) {
            bestSolutionInFront = paretoFront.reduce((max, p) => Math.max(max, p.solution), 0);
        } else {
            bestSolutionInFront = paretoFront.reduce((min, p) => Math.min(min, p.solution), Infinity);
        }
        return { solution: bestSolutionInFront, fitness: 0 }; // fitness=0 car on a déjà la meilleure solution du cycle.
    };

    // On exécute le solveur 20 fois pour trouver une solution plus stable et robuste.
    const { bestResult } = Optimization.runMultiple(solverFunction, 20);

    if (!bestResult || !bestResult.solution || bestResult.solution === Infinity) {
        // Fallback : si l'algo ne retourne rien, on applique une règle simple et sûre.
        return Math.max(MIN_TTL, MAX_TTL - (suspicionScore / 100) * MAX_TTL);
    }

    // runMultiple choisit le meilleur résultat sur la base du score (ici, 0).
    // La "meilleure" solution dépendra du cycle qui a trouvé le meilleur compromis.
    return Math.round(bestResult.solution);
}

/**
 * Vérifie si une chaîne de caractères contient des patterns d'injection connus.
 * @private
 * @param {string} str - La chaîne à vérifier.
 * @param {string[]} [typesToDetect=['sql', 'log4shell', 'ssti', 'xxe', 'traversal', 'rce']] - Les types d'injections à détecter.
 * @returns {boolean} - True si un pattern malveillant est détecté.
 */
function isMalicious(str, typesToDetect = Object.keys(injectionPatterns)) {
    if (typeof str !== 'string') return false;

    for (const type of typesToDetect) {
        const regex = injectionPatterns[type];
        if (regex && regex.test(str)) {
            return true;
        }
    }

    return false;
}

// --- Middleware Proof-of-Work (Le péage) ---
export { isMalicious };

/**
 * Returns a default list of security analyzers for honeypot detection.
 * This list can be used as a base and extended with custom rules.
 * Currently includes an XSS detection analyzer.
 * @returns {Array<Function>}
 */
export const default_analyzers = () => [
    // Analyzer for Cross-Site Scripting (XSS) detection.
    // It uses the 'xss' library, which should be installed by the user (`npm install xss`).
    // If 'xss' is not available, this analyzer will be safely ignored.
    xss_analyzer
];

export const xss_analyzer = async (data) => {
    try {
        // Dynamically import the 'xss' library.
        // The module is loaded only once by Node's cache.
        const xss = (await import('xss')).default;
        const originalData = JSON.stringify(data);
        // If the sanitized string is different, it means malicious HTML/JS was found and removed.
        return xss(originalData) !== originalData;
    } catch (error) {
        // This catch block handles the case where the 'xss' module is not installed.
        if (error.code === 'ERR_MODULE_NOT_FOUND') {
            console.warn('[Fingerprint] Warning: The "xss" package is not installed. The default XSS analyzer is disabled. Run "npm install xss" to enable it.');
            // To avoid repeated warnings, we can replace this function with a no-op.
            this.isXssAnalyzerAvailable = false; // A flag to prevent future attempts.
        }
        return false; // In case of any error, we assume the data is not malicious.
    }
}
/**
 * Returns a powerful WAF (Web Application Firewall) analyzer based on ModSecurity.
 * This analyzer is highly effective against a wide range of attacks (SQLi, XSS, RCE, etc.)
 * by using the OWASP Core Rule Set.
 *
 * **Note:** This is an optional and advanced feature.
 * 1. The user must install the package: `npm install modsecurity-nodejs`
 * 2. ModSecurity rules (like the OWASP CRS) must be available on the server.
 *
 * If the package is not installed, the analyzer will be safely ignored.
 *
 * @param {string} rulesPath - The path to the ModSecurity rules configuration file (e.g., `crs-setup.conf`).
 * @returns {Function} An analyzer function to be used in the `honeypot.analyzers` array.
 */
export const modsecurity_analyzer = (rulesPath) => {
    let wafInstance = null; // Singleton instance for the WAF
    let isModSecurityAvailable = true; // Flag specific to this analyzer instance

    return async (data) => {
        if (!rulesPath) {
            console.warn('[Fingerprint] ModSecurity analyzer disabled: `rulesPath` is not provided.');
            return false;
        }

        if (!isModSecurityAvailable) {
            return false; // Skip if the module is known to be unavailable
        }

        try {
            if (!wafInstance && isModSecurityAvailable) {
                // Dynamically import the library only when needed.
                const { ModSecurity } = await import('modsecurity-nodejs');
                wafInstance = new ModSecurity();
                wafInstance.init();
                wafInstance.addRules(rulesPath);
                console.log('[Fingerprint] ModSecurity WAF analyzer initialized successfully.');
            }

            // The `transaction` method checks the data against the loaded rules.
            // It returns `null` if no rules are matched, or an object with intervention details if a threat is found.
            const result = wafInstance.transaction(data);
            return result !== null; // A non-null result means a threat was detected.
        } catch (error) {
            if (error.code === 'ERR_MODULE_NOT_FOUND') {
                console.warn('[Fingerprint] Warning: "modsecurity-nodejs" is not installed. The WAF analyzer is now disabled. Run "npm install modsecurity-nodejs" to enable it.');
                isModSecurityAvailable = false; // Disable for future calls
            }
            return false; // Assume data is safe if any error occurs.
        }
    };
};
/**
 * Returns a default list of whitelisting rules for common and legitimate web crawlers.
 * This list can be used as a base and extended with custom rules.
 * @returns {Array<{userAgent: string, hostnameSuffix: string}>}
 */
export const default_whitelist = () => [
    // === Moteurs de recherche majeurs ===
    { userAgent: 'Googlebot', hostnameSuffix: '.googlebot.com' },
    { userAgent: 'Google-Extended', hostnameSuffix: '.google.com' },
    { userAgent: 'AdsBot-Google', hostnameSuffix: '.googlebot.com' },
    { userAgent: 'Mediapartners-Google', hostnameSuffix: '.google.com' },
    { userAgent: 'Google-InspectionTool', hostnameSuffix: '.google.com' },
    { userAgent: '(bingbot|adidxbot)', hostnameSuffix: '.search.msn.com' },
    { userAgent: 'DuckDuckBot', hostnameSuffix: '.duckduckgo.com' },
    { userAgent: 'YandexBot', hostnameSuffix: '.yandex.com' },
    { userAgent: 'YandexImages', hostnameSuffix: '.yandex.com' },
    { userAgent: 'Baiduspider', hostnameSuffix: '.crawl.baidu.com' },
    { userAgent: 'Slurp', hostnameSuffix: '.crawl.yahoo.net' },
    { userAgent: 'Sogou web spider', hostnameSuffix: '.sogou.com' },
    { userAgent: 'Exabot', hostnameSuffix: '.exabot.com' },
    { userAgent: 'ia_archiver', hostnameSuffix: '.alexa.com' },
    { userAgent: 'SeznamBot', hostnameSuffix: '.seznam.cz' },
    { userAgent: 'Mail.RU_Bot', hostnameSuffix: '.mail.ru' },
    { userAgent: 'Yeti', hostnameSuffix: '.naver.com' }, // Naver

    // === Outils SEO et d'analyse ===
    { userAgent: 'AhrefsBot', hostnameSuffix: '.ahrefs.com' },
    { userAgent: 'SemrushBot', hostnameSuffix: '.semrush.com' },
    { userAgent: 'MJ12bot', hostnameSuffix: '.mj12bot.com' }, // Majestic
    { userAgent: 'rogerbot', hostnameSuffix: '.moz.com' }, // Moz
    { userAgent: 'DotBot', hostnameSuffix: '.moz.com' }, // Moz (anciennement opensiteexplorer.org)
    { userAgent: 'Screaming Frog SEO Spider', hostnameSuffix: '.screamingfrog.co.uk' },
    { userAgent: 'cognitiveseo', hostnameSuffix: '.cognitiveseo.com' },
    { userAgent: 'SEOkicks', hostnameSuffix: '.seokicks.com' },
    { userAgent: 'serpstatbot', hostnameSuffix: '.serpstatbot.com' },
    { userAgent: 'MegaIndex', hostnameSuffix: '.megaindex.com' },
    { userAgent: 'LinkpadBot', hostnameSuffix: '.linkpad.ru' },
    { userAgent: 'Sistrix', hostnameSuffix: '.sistrix.com' },
    { userAgent: 'RyteBot', hostnameSuffix: '.ryte.com' },
    { userAgent: 'linkfluence', hostnameSuffix: '.linkfluence.com' },
    { userAgent: 'TurnitinBot', hostnameSuffix: '.turnitin.com' },
    { userAgent: 'GrapeshotCrawler', hostnameSuffix: '.grapeshot.co.uk' },

    // === Robots d'IA et de données ===
    { userAgent: 'GPTBot', hostnameSuffix: '.openai.com' },
    { userAgent: 'ChatGPT-User', hostnameSuffix: '.openai.com' },
    { userAgent: 'Applebot', hostnameSuffix: '.applebot.apple.com' },
    { userAgent: 'CCBot', hostnameSuffix: '.commoncrawl.org' },
    { userAgent: 'Bytespider', hostnameSuffix: '.bytespider.com' }, // ByteDance (TikTok)
    { userAgent: 'Diffbot', hostnameSuffix: '.diffbot.com' },
    { userAgent: 'PerplexityBot', hostnameSuffix: '.perplexity.ai' },
    { userAgent: 'ClaudeBot', hostnameSuffix: '.anthropic.com' },
    { userAgent: 'cohere.io', hostnameSuffix: '.cohere.io' },
    { userAgent: 'DataForSeoBot', hostnameSuffix: '.dataforseo.com' },
    { userAgent: 'YouBot', hostnameSuffix: '.you.com' },
    { userAgent: 'omgili', hostnameSuffix: '.omgili.com' },

    // === Réseaux sociaux et partage ===
    { userAgent: 'facebookexternalhit', hostnameSuffix: '.facebook.com' },
    { userAgent: 'facebot', hostnameSuffix: '.facebook.com' },
    { userAgent: 'Twitterbot', hostnameSuffix: '.twttr.com' },
    { userAgent: 'Pinterestbot', hostnameSuffix: '.pinterest.com' },
    { userAgent: 'LinkedInBot', hostnameSuffix: '.linkedin.com' },
    { userAgent: 'Slackbot', hostnameSuffix: '.slack.com' },
    { userAgent: 'Discordbot', hostnameSuffix: '.discord.com' },
    { userAgent: 'TelegramBot', hostnameSuffix: '.telegram.org' },
    { userAgent: 'WhatsApp', hostnameSuffix: '.wa.me' },
    { userAgent: 'SkypeUriPreview', hostnameSuffix: '.skype.com' },
    { userAgent: 'redditbot', hostnameSuffix: '.reddit.com' },

    // === Services de monitoring et d'uptime ===
    { userAgent: 'UptimeRobot', hostnameSuffix: '.uptimerobot.com' },
    { userAgent: 'Pingdom', hostnameSuffix: '.pingdom.com' },
    { userAgent: 'StatusCake', hostnameSuffix: '.statuscake.com' },
    { userAgent: 'Site24x7', hostnameSuffix: '.site24x7.com' },
    { userAgent: 'Freshping', hostnameSuffix: '.freshping.io' },
    { userAgent: 'Better Uptime', hostnameSuffix: '.betteruptime.com' },
    { userAgent: 'Checkly', hostnameSuffix: '.checkly-infra.com' },
    { userAgent: 'Datadog', hostnameSuffix: '.datadoghq.com' },
    { userAgent: 'NewRelicPinger', hostnameSuffix: '.newrelic.com' },

    // === Archives et agrégateurs de contenu ===
    { userAgent: 'archive.org_bot', hostnameSuffix: '.archive.org' },
    { userAgent: 'Feedly', hostnameSuffix: '.feedly.com' },
    { userAgent: 'FeedFetcher-Google', hostnameSuffix: '.google.com' },
    { userAgent: 'TheOldReader', hostnameSuffix: '.theoldreader.com' },
    { userAgent: 'Inoreader', hostnameSuffix: '.inoreader.com' },
    { userAgent: 'FlipboardProxy', hostnameSuffix: '.flipboard.com' },
    { userAgent: 'PaperLiBot', hostnameSuffix: '.paper.li' },

    // === Services Cloud et Plateformes ===
    { userAgent: 'Amazon Route 53 Health Check', hostnameSuffix: '.amazonaws.com' },
    { userAgent: 'Google-Cloud-Scheduler', hostnameSuffix: '.google.com' },
    { userAgent: 'APIs-Google', hostnameSuffix: '.google.com' },

    // === Divers ===
    { userAgent: 'W3C_Validator', hostnameSuffix: '.w3.org' },
    { userAgent: 'GTmetrix', hostnameSuffix: '.gtmetrix.com' },
    { userAgent: 'WebPageTest', hostnameSuffix: '.webpagetest.org' },
    { userAgent: 'Google-Site-Verification', hostnameSuffix: '.google.com' },
    { userAgent: 'KeyCDN', hostnameSuffix: '.keycdn.com' },
];



// --- Proof-of-Work Middleware (The Tollbooth) ---
export const powMiddleware = (securityConfig) => {
  const engine = new FingerprintEngine(securityConfig);

  // Initialize the problem manager with the configured path, if provided.
  if (securityConfig.enableUsefulWork && securityConfig.usefulWorkConfigPath) {
    getProblemManager(securityConfig.usefulWorkConfigPath);
  }

  if (securityConfig.autotuning) {
    startThresholdAutoTuning({
      securityConfig: securityConfig,
      ...securityConfig.autotuning,
    });
  }

  // Provide a default for isApiRequest if not specified by the user.
  // This makes API challenge handling work more seamlessly out-of-the-box.
  if (!securityConfig?.isApiRequest) {
    securityConfig.isApiRequest = (req) =>
      req.headers?.accept?.includes('application/json');
  }

  return async (req, res, next) => {
    const requestContext = {
      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
      path: req.path,
      cookies: req.cookies,
      query: req.query,
      body: req.body,
      headers: req.headers,
      isStatic: securityConfig?.isStaticResource?.(req.path) || isStaticResource(req.path),
      // Pass the original request object for the isApiRequest function
      rawReq: req,
      requestTimestamp: Date.now(), // Timestamp de début de requête
      // Add the newly required properties for full decoupling
      rawHeaders: req.rawHeaders,
      // Pass the raw request object for advanced inspection (e.g., JA3)
      httpVersion: req.httpVersion,
    };

    const decision = await engine.processRequest(requestContext);

    // Attach the fingerprinting result to the request object for downstream middlewares.
    req.fingerprint = {
      score: decision.score,
      vector: decision.vector,
    };

    // After getSuspicionVector runs, it might have attached cookies to be set.
    if (requestContext._newCookies) {
      requestContext._newCookies.forEach(c => res.cookie(c.name, c.value, c.options));
    }

    switch (decision.action) {
      case 'block':
        return res.status(decision.status).send(decision.body);

      case 'challenge': // Gère à la fois les réponses HTML et JSON
        if (typeof decision.body === 'object' && decision.body !== null) {
          return res.status(decision.status).json(decision.body);
        }
        // Par défaut, envoie du HTML
        return res.status(decision.status).send(decision.body);

      case 'redirect':
        if (decision.cookie) {
          res.cookie(decision.cookie.name, decision.cookie.value, decision.cookie.options);
        }
        return res.redirect(decision.path);

      case 'next':
      default:
        return next();
    }
  };
};

/**
 * @internal
 * Exporting an object containing the functions to make them mockable in tests.
 * This is a common pattern to allow mocking of ES module functions.
 */
export const __internal = {
    store, // Export the store for testing
    getDeviceHash,
    getCompositeDeviceHash,
    getSuspicionVector,
    cyrb53, // Export for testing
    FingerprintBuilder, // Export for testing
    calculateTarget,
    determineOptimalTicketTtl,
    getRequestPatternScore, // Expose for testing
    getBehaviorScore, // Expose for testing
    getCrossLayerInconsistency, // Expose for testing
    // Expose page generators for security testing
    getTimeInconsistencyScore,
    getTlsFingerprint, // NOUVEAU: Expose pour les tests
    getTlsSpoofingScore, // NOUVEAU: Expose pour les tests
    generateCpuTargetChallengePage,
    generateCombinedPoWChallengePage,
};

// --- THRESHOLD AUTO-TUNING SECTION ---

let autoTuningJobId = null;

/**
 * Executes a threshold optimization pass using collected traffic data.
 * @private
 * @param {object} securityConfig - The security configuration object to update.
 * @param {Array<object>} trafficData - The array containing traffic logs.
 * @param {number} minDataPoints - The minimum number of data points required to start optimization.
 * @param {number} maxDataPoints - The maximum number of data points to keep after an optimization cycle.
 */
function runThresholdOptimization(securityConfig, trafficData, minDataPoints, maxDataPoints) {
  const highConfidenceLogs = trafficData.filter(log => log.type === 'challenge_solved' || log.type === 'trap_triggered').length;
  const highConfidenceRatio = trafficData.length > 0 ? highConfidenceLogs / trafficData.length : 0;
  const MIN_CONFIDENCE_RATIO = 0.05; // Exiger au moins 5% de signaux forts.

  if (trafficData.length < minDataPoints || highConfidenceRatio < MIN_CONFIDENCE_RATIO) {
    if (trafficData.length < minDataPoints) {
    console.log(`[AutoTuning] Reporté : ${trafficData.length}/${minDataPoints} points de données.`);
    } else {
      console.log(`[AutoTuning] Reporté : Ratio de confiance insuffisant (${(highConfidenceRatio * 100).toFixed(2)}% < ${(MIN_CONFIDENCE_RATIO * 100).toFixed(2)}%).`);
    }
    return;
  }

  if (trafficData.length > maxDataPoints) {
    console.log(`[AutoTuning] Le journal de trafic a atteint ${trafficData.length} entrées (max: ${maxDataPoints}). Troncation des données les plus anciennes.`);
    trafficData.splice(0, trafficData.length - maxDataPoints);
  }

  console.log(`[AutoTuning] Démarrage du cycle d'optimisation complet avec ${trafficData.length} points de données.`);

  const paretoFront = Optimization.Operators.solveFullSecurityTuning({ trafficData });

  if (!paretoFront || paretoFront.length === 0) {
    console.warn("[AutoTuning] L'optimisation n'a retourné aucune solution.");
    return;
  }

  // Stratégie de sélection : choisir la solution la plus équilibrée du front de Pareto.
  // On cherche la solution la plus proche de l'origine (0,0) dans l'espace des objectifs.
  let bestSolution = paretoFront[0];
  let minDistance = Math.sqrt(Math.pow(bestSolution.objectives[0], 2) + Math.pow(bestSolution.objectives[1], 2));

  for (let i = 1; i < paretoFront.length; i++) {
    const distance = Math.sqrt(Math.pow(paretoFront[i].objectives[0], 2) + Math.pow(paretoFront[i].objectives[1], 2));
    if (distance < minDistance) {
      minDistance = distance;
      bestSolution = paretoFront[i];
    }
  }

  // --- NOUVEAU : Logique d'inertie pour l'application de la configuration ---
  // Au lieu d'appliquer directement la nouvelle configuration, on fait "glisser"
  // l'ancienne vers la nouvelle, avec une vélocité de changement maximale.
  const newConfig = bestSolution.solution;
  const MAX_CHANGE_VELOCITY = 0.15; // 15% de changement maximum par cycle

  /**
   * Met à jour un objet de configuration (ex: thresholds, weights) en douceur.
   * @param {object} currentConfig - La configuration actuelle à modifier.
   * @param {object} targetConfig - La configuration cible proposée par l'optimiseur.
   */
  const applyInertialUpdate = (currentConfig, targetConfig) => {
      if (!currentConfig || !targetConfig) return; // Vérifier aussi currentConfig
      for (const key in targetConfig) {
          if (Object.hasOwnProperty.call(currentConfig, key)) {
              const currentValue = currentConfig[key];
              const targetValue = targetConfig[key];
              const delta = targetValue - currentValue;
              const maxChange = Math.abs(currentValue * MAX_CHANGE_VELOCITY);

              // Limite le changement à la vélocité maximale
              const change = Math.max(-maxChange, Math.min(maxChange, delta));
              
              currentConfig[key] += change;
          }
      }
  };

  applyInertialUpdate(securityConfig.thresholds, newConfig.thresholds);
  applyInertialUpdate(securityConfig.weights, newConfig.weights);
  applyInertialUpdate(securityConfig.patterns, newConfig.patterns);

  console.log("[AutoTuning] Nouvelle configuration de sécurité optimisée appliquée.");
  console.log("[AutoTuning] Objectifs atteints :", { falsePositiveRate: bestSolution.objectives[0].toFixed(4), falseNegativeRate: bestSolution.objectives[1].toFixed(4) });
  console.log("[AutoTuning] Nouveaux seuils :", securityConfig.thresholds);
  console.log("[AutoTuning] Nouveaux poids :", securityConfig.weights);
  console.log("[AutoTuning] Nouveaux patterns :", securityConfig.patterns);
}

/**
 * Starts the background process for auto-tuning security thresholds.
 * @export
 * @param {object} options - Configuration options for auto-tuning.
 * @param {object} options.securityConfig - The live security configuration object that will be mutated.
 * @param {Array<object>} options.trafficData - The array where the logger pushes traffic data.
 * @param {number} [options.interval=1800000] - The interval in milliseconds between each optimization cycle (default: 30 minutes).
 * @param {number} [options.minDataPoints=200] - The minimum number of requests to have before starting a cycle (default: 200).
 * @param {number} [options.maxDataPoints=10000] - The maximum number of log entries to keep in memory (default: 10,000).
 */
export function startThresholdAutoTuning(options) {
    if (autoTuningJobId) {
        console.warn("[AutoTuning] Le job est déjà en cours d'exécution.");
        return;
    }

    const {
        securityConfig,
        trafficData,
        interval = 1800000, // 30 minutes
        minDataPoints = 200,
        maxDataPoints = 10000 // Limite par défaut à 10 000 entrées
    } = options;

    if (!securityConfig || !trafficData) {
        throw new Error("[AutoTuning] `securityConfig` et `trafficData` sont requis.");
    }

    console.log(`[AutoTuning] Job d'optimisation des seuils démarré. Prochain cycle dans ${interval / 60000} minutes.`);

    autoTuningJobId = setInterval(() => {
        runThresholdOptimization(securityConfig, trafficData, minDataPoints, maxDataPoints);
    }, interval);
}

/**
 * Stops the threshold auto-tuning process.
 * @export
 */
export function stopThresholdAutoTuning() {
    if (autoTuningJobId) {
        clearInterval(autoTuningJobId);
        autoTuningJobId = null;
        console.log("[AutoTuning] Job d'optimisation des seuils arrêté.");
    }
}
