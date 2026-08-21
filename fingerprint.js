// C:/Dev/games.primals.net/src/utils/fingerprint.js
import crypto from "node:crypto";
import { Optimization } from "./library.js";
import { cyrb53, FingerprintBuilder } from "./fingerprint.builder.js";

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
    return cyrb53(headerKeys.join(','));
}
export function getDeviceHash(context) {
    // Prioritize the rich client-side fingerprint if provided.
    const clientFp = context.headers['x-device-fingerprint'];
    if (clientFp && typeof clientFp === 'string' && clientFp.includes('cvs:')) {
        // Basic validation to ensure it looks like our client-side fingerprint.
        return clientFp;
    }

    // Fallback to server-side only fingerprinting if the header is missing.
    const srv = new FingerprintBuilder();
    srv.add("ua", context.headers["user-agent"]);
    if (context.headers["sec-ch-ua-platform"])
        srv.add("os", context.headers["sec-ch-ua-platform"]);
    if (context.headers["sec-ch-ua"]) srv.add("ch", context.headers["sec-ch-ua"]);
    srv.add("h_ord", getHeaderSignature(context));
    return srv.toString();
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
  return `
      <html>
        <head><title>Advanced Security Check (Level 3)</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Ultimate Verification (Level 3)</h1>
          <p>Please solve this small optimization problem to prove you are human.</p>
          <div id="loader" style="margin:20px;">⚙️ Calculating route... (${numCities} cities)</div>
          <script>
            const cities = ${citiesJson};
            const nonce = "${nonce}";
            const targetMaxDistance = ${targetMaxDistance};

            // Utility function to calculate the distance between two cities
            function distance(city1, city2) {
                return Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2));
            }

            // Utility function to evaluate the total distance of a path
            function evaluatePathDistance(cities, path) {
                let totalDistance = 0;
                for (let i = 0; i < path.length - 1; i++) {
                    totalDistance += distance(cities[path[i]], cities[path[i + 1]]);
                }
                totalDistance += distance(cities[path[path.length - 1]], cities[path[0]]); // Return to start
                return totalDistance;
            }

            // Solveur simple du TSP (heuristique du plus proche voisin)
            function solveTspNearestNeighbor(cities) {
                const numCities = cities.length;
                if (numCities === 0) return [];

                let currentPath = [];
                let visited = new Array(numCities).fill(false);

                let currentCityIndex = 0; // Always start with the first city for reproducibility
                currentPath.push(currentCityIndex);
                visited[currentCityIndex] = true;

                for (let i = 1; i < numCities; i++) {
                    let nearestCityIndex = -1;
                    let minDistance = Infinity;

                    for (let j = 0; j < numCities; j++) {
                        if (!visited[j]) {
                            const dist = distance(cities[currentCityIndex], cities[j]);
                            if (dist < minDistance) {
                                minDistance = dist;
                                nearestCityIndex = j;
                            }
                        }
                    }
                    currentCityIndex = nearestCityIndex;
                    currentPath.push(currentCityIndex);
                    visited[currentCityIndex] = true;
                }
                return currentPath;
            }

            async function solve() {
              // To avoid freezing the browser, yield the thread from time to time
              await new Promise(resolve => setTimeout(resolve, 10));
              const solutionPath = solveTspNearestNeighbor(cities);
              const solutionDistance = evaluatePathDistance(cities, solutionPath);

              if (solutionDistance <= targetMaxDistance) {
                window.location.href = "${path}" + "?pow_type=tsp&pow_nonce=" + nonce + "&pow_solution=" + JSON.stringify(solutionPath);
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
export const verifyMemoryPoW = (nonce, solution, difficulty = 16, clientSecret) => {
  const size = difficulty * 1024 * 1024;
  const iterations = size / 16;
  const buffer = new Uint32Array(size / 4);
  const seed = clientSecret ? `${nonce}:${clientSecret}` : nonce;
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
  if (!ticket) return false;
  const [expiry, sig] = ticket.split(":");
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

  // 3. Check for injection attempts in values
  if (detectInjections) {
    // Regex for common SQL injection patterns
    // WARNING: These are generic and may cause false positives.
    // Consider using a dedicated WAF library or more specific regex for your application.
    const sqlRegex = new RegExp(
      "('|\"|;|--|#|/\\*.*\\*/)|\\b(union|select|insert|update|delete|drop|truncate|from|where|and|or)\\b",
      "i"
    );
    // Regex for common NoSQL (MongoDB) injection patterns (e.g., keys starting with '$')
    // This looks for keys like "$where", "$ne", etc. in a stringified JSON.
    const nosqlKeyRegex = /"\$(where|ne|gt|lt|in|nin)":/;
    // Regex for common Remote Code Execution (RCE) patterns
    const rceRegex = new RegExp(
      // File traversal, command execution functions, and shell commands
      // Added process, child_process to catch Node.js specific RCE.
      "(\\.\\./|\\.\\.\\\\)|\\b(exec|system|shell_exec|passthru|popen|proc_open|eval|assert|require|include|process|child_process)(_once)?\\s*\\(|\\b(wget|curl|bash|sh|powershell|php)\\b",
      "i"
    );

    const inspect = (obj) => {
        for (const key in obj) {
            if (Object.prototype.hasOwnProperty.call(obj, key)) {
                const value = obj[key];
                if (typeof value === 'string') {
                    if (rceRegex.test(value) || sqlRegex.test(value)) return true;
                } else if (typeof value === 'object' && value !== null) {
                    // For NoSQL, we check the stringified version of the object to find keys like "$gt"
                    // This is more accurate when done on the object itself.
                    if (nosqlKeyRegex.test(JSON.stringify(value))) return true;
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
 * Analyzes server-side request patterns for a given device to detect bot-like behavior.
 * This is a stateful check that looks for repetitive or unnaturally fast requests.
 * @param {object} context - The request context.
 * @param {object} deviceData - The device's activity data from the store.
 * @returns {{requestPatternScore: number}}
 */
function getRequestPatternScore(context, deviceData, patternConfig = {}) {
    if (!deviceData) return { requestPatternScore: 0 };

    // Default values for the pattern detection logic, which can be overridden by the auto-tuner.
    const {
        velocityThreshold = 200, velocityWeight = 30,
        burstThreshold = 500, burstWeight = 50,
        scrapeThreshold = 1000, scrapeWeight = 20, scrapeBurstWeight = 40,
        historySize = 10,
        decayFactor = 0.9,
        inactivityReset = 30000
    } = patternConfig;

    const now = Date.now();
    const currentPath = context.path;
    // Make the function robust to handle both URLSearchParams and plain objects for query.
    // Ensure query parameters are consistently handled, whether they come from a URLSearchParams object or a plain object.
    const params = context.query instanceof URLSearchParams ? context.query : new URLSearchParams(context.query);
    params.sort(); // Sort for deterministic order
    const currentQueryString = params.toString();

    // Initialize request history if it doesn't exist
    if (!deviceData.requestHistory) {
        deviceData.requestHistory = [];
    }

    const history = deviceData.requestHistory;
    let score = 0;

    // --- Analyze patterns based on the last few requests ---
    if (history.length > 0) {
        const lastRequest = history[history.length - 1];
        const timeSinceLast = now - lastRequest.timestamp; // 150

        // 1. Velocity Check: Penalize requests that are too fast to be human.
        if (timeSinceLast < velocityThreshold) { // 150 < 200 -> true
            score += velocityWeight; // score = 30
        }

        console.log(currentPath, lastRequest.path,currentQueryString, lastRequest.queryString, timeSinceLast, burstThreshold)
        // 2. Burst Check: Add additional penalty for identical requests in a very short time frame.
        if (currentPath === lastRequest.path && currentQueryString === lastRequest.queryString && timeSinceLast < burstThreshold) { // 150 < 500 -> true
            score += burstWeight; // score = 30 + 50 = 80
        }

        // 3. Sequential Scraping Check: Add additional penalty for same path with different query params (potential scraping).
        // This is a simplified check, now independent of the burst check.
        if (currentPath === lastRequest.path && currentQueryString !== lastRequest.queryString && timeSinceLast < scrapeThreshold) {
            const previousRequest = history.length > 2 ? history[history.length - 2] : null;
            if (previousRequest && previousRequest.path === currentPath) {
                score += scrapeBurstWeight; // This is at least the 3rd request in a sequence to the same path.
            } else {
                score += scrapeWeight; // First sign of a potential scraping pattern
            }
        }
    }

    // --- Update history ---
    history.push({
        timestamp: now,
        path: currentPath,
        queryString: currentQueryString,
    });

    // Keep history to a reasonable size (e.g., last 10 requests)
    if (history.length > historySize) {
        history.shift();
    }

    // Decay the score over time if behavior becomes normal again.
    // We can store the score in deviceData and decay it.
    deviceData.lastPatternScore = (deviceData.lastPatternScore || 0) * decayFactor + score; // Decay old score and add new

    // If there hasn't been a request in a while, reset the pattern score.
    if (history.length > 1 && (now - history[history.length - 2].timestamp > inactivityReset)) { // X ms inactivity
        deviceData.lastPatternScore = 0;
    }

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
 * @property {(key: string, value: any) => Promise<void>} set
 * @property {(key: string) => Promise<boolean>} has
 * @property {(key: string) => Promise<void>} delete
 */

/**
 * Default in-memory store implementation.
 * @type {IStore}
 */
const inMemoryStore = {
  _map: new Map(),
  async get(key) { return this._map.get(key); },
  async set(key, value) { this._map.set(key, value); },
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
async function resolveRequestIdentity(context) {
  const existingDeviceId = context.cookies?.device_id;
  const currentDeviceHash = getDeviceHash(context);
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
        httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "strict", maxAge: 31536000000, // 1 year
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

  const currentFpHash = getDeviceHash(context); // Use the device hash

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
    const { deviceId, deviceData, consistencyScore, newCookie } = await resolveRequestIdentity(context);

  const clientIp = context.clientIp;

  // If a new cookie needs to be set, attach it to the request object
  // so the middleware can handle it. This is a temporary state holder.
  if (newCookie) {
    context._newCookies = context._newCookies || [];
    context._newCookies.push(newCookie);
  }
  await store.set(`ip-device:${clientIp}`, deviceId); // Link the IP to the device

  // Periodically clean up device data
  if (Date.now() - deviceData.lastUpdate > 10 * 60 * 1000) { // 10 minutes
    deviceData.ips.clear();
    deviceData.rapidChangeCount = 0;
  }
  deviceData.lastUpdate = Date.now();

  const behavioral = await getBehavioralIndicators(context, deviceData);
  const { headerAnomalyScore } = getHeaderAnomalies(context);
  // Calculate the inconsistency score here, separately.
  const inconsistencyScore = Math.min(100, Math.max(0, (1 - consistencyScore) * 200)); // Amplified score


  // Save the updated device state to the store
  // Note: deviceData.ips is a Set, which may not serialize correctly in all stores (e.g., JSON). A Redis store should handle this via custom serialization or by converting to an array.
  await store.set(`device:${deviceId}`, deviceData);

  return { ...behavioral, headerAnomalyScore, inconsistencyScore };
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
function calculateTarget(suspicionFactor) {
  // Difficulty range adjusted to be realistic.
  // MIN_DIFFICULTY: Fast enough not to bother a slightly suspicious user.
  // MAX_DIFFICULTY: Slow enough to heavily penalize a bot, but feasible for a patient human (5-30s).
  const MIN_DIFFICULTY_BITS = 18; // Default value, should be configurable
  const MAX_DIFFICULTY_BITS = 26; // Default value, should be configurable

  // Use linear interpolation between min and max difficulty.
  const totalDifficultyBits =
    MIN_DIFFICULTY_BITS +
    suspicionFactor * (MAX_DIFFICULTY_BITS - MIN_DIFFICULTY_BITS);

  // The target is max / 2^bits
  return MAX_DIFFICULTY_TARGET >> BigInt(Math.floor(totalDifficultyBits));
}

/**
 * Generates a CPU challenge based on a target.
 */
export function generateCpuTargetChallenge(
  clientIp,
  nonce,
  suspicionFactor,
  originalUrl,
) {
  const target = calculateTarget(suspicionFactor);
  return {
    type: "cpu_target",
    nonce: nonce,
    target: target.toString(16), // Send the target in hexadecimal
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
    return `
      <html><head><title>Security Check</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h1>Please wait... (Level 1)</h1>
        <p>We are verifying that you are not a bot. This may take a few seconds.</p>
        <div id="loader" style="margin:20px;">⚙️ Performing CPU security calculation...</div>
        <script>
          async function solve() {
            const target = BigInt("0x${target}");
            let solution = 0;
            while (true) {
              const msg = "${clientIp}:${nonce}:" + solution;
              const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
              const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
              if (BigInt('0x' + hashHex) < target) {
                window.location.href = "${path}?pow_type=cpu_target&pow_nonce=${nonce}&pow_solution=" + solution;
                break;
              }
              solution++;
              if (solution % 100000 === 0) await new Promise(r => setTimeout(r, 0));
            }
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
function generateCombinedPoWChallengePage(cpuChallengeDetails, memoryDifficulty, clientIp, clientSecret) {
    const { nonce, target, path } = cpuChallengeDetails;
    return `
      <html><head><title>Advanced Security Check</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h1>Enhanced Verification... (Level 2)</h1>
        <p>Your activity requires an additional security check. This may take a few moments.</p>
        <div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div>
        <script>
          async function solve() {
            const nonce = "${nonce}";
            const path = "${path}";
            const clientSecret = "${clientSecret}"; // Secret is now available to the client

            // --- CPU Challenge ---
            document.getElementById('loader').innerText = '⚙️ Performing CPU security calculation...';
            const cpuTarget = BigInt("0x${target}");
            let cpuSolution = 0;
            while (true) {
              const msg = "${clientIp}:${nonce}:" + cpuSolution + ":" + clientSecret;
              const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
              const hashHex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
              if (BigInt('0x' + hashHex) < cpuTarget) break;
              cpuSolution++;
              if (cpuSolution % 100000 === 0) await new Promise(r => setTimeout(r, 0));
            }

            // --- Memory Challenge ---
            document.getElementById('loader').innerText = '⚙️ Performing memory allocation and calculation... (${memoryDifficulty} MB)';
            await new Promise(r => setTimeout(r, 10)); // Yield to update UI

            let memSolution = 0;
            try {
                const size = ${memoryDifficulty} * 1024 * 1024;
                const iterations = size / 16;
                const buffer = new Uint32Array(size / 4);
                const seed = nonce + ":" + clientSecret;
                let h = new TextEncoder().encode(seed).reduce((acc, v) => acc + v, 0);
                for (let i = 0; i < buffer.length; i++) {
                    buffer[i] = h = Math.imul(h ^ i, 1597334677);
                }
                for(let i = 0; i < iterations; i++) {
                    const addr = buffer[i % buffer.length] % buffer.length;
                    memSolution ^= buffer[addr];
                }
            } catch(e) {
                document.getElementById('loader').innerText = "Error: Insufficient memory. Please refresh.";
                return;
            }
            window.location.href = path + "?pow_type=cpu_mem&pow_nonce=" + nonce + "&pow_solution_cpu=" + cpuSolution + "&pow_solution_mem=" + memSolution;
          }
          solve();
        </script>
      </body></html>`;
}

/**
 * Verifies a PoW solution based on a target and generates a ticket.
 */
export function verifyCpuTargetPoWAndGenerateTicket(
  clientIp,
  nonce,
  solution,
  suspicionFactor,
  clientSecret, // Le secret est maintenant requis
) {
  const target = calculateTarget(suspicionFactor);
  const message = clientSecret ? `${clientIp}:${nonce}:${solution}:${clientSecret}` : `${clientIp}:${nonce}:${solution}`;
  const hash = crypto
    .createHash("sha256")
    .update(message)
    .digest("hex");
  const hashAsInt = BigInt("0x" + hash);

  if (hashAsInt < target) {
    // The comparison is direct with native BigInts
    // The proof is valid, generate the ticket
    const expiry = Date.now() + 3600000; // 1 heure
    const signature = crypto
      .createHmac("sha256", getPowSecret())
      .update(`${clientIp}:${expiry}`)
      .digest("hex");
    return `${expiry}:${signature}`;
  }

  return null;
}

const staticExtensions = new RegExp(
  "\\.(js|css|png|jpg|jpeg|gif|svg|mp3|webp|ico|woff|woff2|ttf|otf|map)$",
  "i",
);
const isStaticResource = (path) => staticExtensions.test(path);

// --- Middleware Proof-of-Work (Le péage) ---
class FingerprintEngine {
  constructor(securityConfig) {
    const isProduction = process.env.NODE_ENV === 'production';
    this.securityConfig = securityConfig;
    this.isProduction = isProduction;
  }

  async processRequest(requestContext) {
    const { clientIp, path, cookies, query, isStatic } = requestContext;
    const { weights, thresholds, logger, onDeviceCompromised } = this.securityConfig;

    if (isStatic) {
      return { action: 'next', score: 0, vector: {} };
    }

    const { pow_nonce } = query;

    // Honeypot: Direct probing of challenge endpoints is highly suspicious.
    // A legitimate user only hits these endpoints via the challenge page itself, which is only served to suspicious users.
    // If we see a pow_nonce on a request that isn't (yet) considered suspicious, it's a bot.
    // We check this early, before the main suspicion calculation.
    if (pow_nonce) {
        const powCookie = cookies?.pow_clearance;
        if (!isTicketValid(clientIp, powCookie)) { // Only check if there's no valid ticket
            // This is a potential probe. We'll let the main logic confirm if it's not a legitimate challenge response.
        }
    }

    // Check for persisted "condemned" status early.
    const { deviceData } = await resolveRequestIdentity(requestContext);
    if (deviceData?.condemned) {
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Previously condemned', score: 100, vector: { honeypotScore: 100 } });
        }
        return { action: 'block', status: 403, body: 'Forbidden', score: 100, vector: { honeypotScore: 100 } };
    }

    // The engine now works with the context directly, no more rawReq dependency here.
    const suspicionVector = await __internal.getSuspicionVector(requestContext, this.securityConfig);
    const { honeypotScore } = getHoneypotScore(requestContext, this.securityConfig.honeypot);
    const { requestPatternScore } = getRequestPatternScore(requestContext, deviceData, this.securityConfig.patterns);
    suspicionVector.honeypotScore = honeypotScore;
    suspicionVector.requestPatternScore = requestPatternScore;

    const finalScore =
      suspicionVector.historyScore * (weights.historyScore || 0) +
      suspicionVector.rotationScore * (weights.rotationScore || 0) +
      suspicionVector.headerAnomalyScore * (weights.headerAnomalyScore || 0) + suspicionVector.requestPatternScore * (weights.requestPatternScore || 0) +
      suspicionVector.inconsistencyScore * (weights.inconsistencyScore || 0) +
      honeypotScore * (weights.honeypotScore || 0);

    const isBlocked = finalScore >= (thresholds.block || 95);

    const isSuspiciousHigh = finalScore >= thresholds.high && !isBlocked;
    const isSuspiciousMedium = finalScore >= thresholds.medium;
    const isSuspicious = finalScore >= thresholds.low;

    // Calculate an analog "suspicion factor" (0 to 1+) for progressive difficulty
    const suspicionFactor = isSuspicious
        ? Math.min(
            1,
            (finalScore - thresholds.low) / (thresholds.high - thresholds.low),
        )
        : 0;
    const powCookie = cookies?.pow_clearance;
    const { pow_type, pow_solution, pow_solution_cpu, pow_solution_mem } = query;

    // Honeypot: Direct probing of challenge endpoints is highly suspicious.
    // A legitimate user only hits these endpoints via the challenge page itself.
    if (pow_nonce && !isSuspicious) {
      if (logger) {
          logger({ type: 'honeypot_probe', deviceId: cookies?.device_id, score: finalScore, path: path, timestamp: Date.now() });
      }
      suspicionVector.honeypotScore = 100; // Bot is probing. Max penalty.
      // Recalculate score and block immediately.
      const newFinalScore = finalScore - (honeypotScore * (weights.honeypotScore || 0)) + (100 * (weights.honeypotScore || 0));
      return { action: 'block', status: 403, body: 'Forbidden', score: newFinalScore, vector: suspicionVector };
    }

    // If the action is to block, we should still include the score and vector for logging/testing.
    if (isBlocked) {
      if (onDeviceCompromised) {
        onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Score exceeded block threshold', score: finalScore, vector: suspicionVector });
      }
      return { action: 'block', status: 403, body: 'Forbidden', score: finalScore, vector: suspicionVector };
    }

    // Honeypot: Check if the request is for a trap URL generated in a previous challenge.
    // This requires a nonce from a *previous* challenge, which we can look up via the device ID.
    const lastNonce = deviceData?.lastChallengeNonce;
    if (lastNonce && query.sig && verifyTrapUrl(path, query.sig, lastNonce)) {
        deviceData.condemned = true; // This device is a bot. Condemn it.
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Triggered signed honeypot trap URL', score: 100, vector: { honeypotScore: 100 } });
        }
        await store.set(`device:${cookies.device_id}`, deviceData);
        return { action: 'block', status: 403, body: 'Forbidden', score: 100, vector: { honeypotScore: 100 } };
    }

    if (isSuspicious && !isTicketValid(clientIp, powCookie)) {
        // --- CHALLENGE SOLUTION HANDLING ---
        if (pow_nonce && (pow_solution || (pow_solution_cpu && pow_solution_mem))) {
            let isValid = false,
                // Retrieve the client-side secret associated with this nonce
                clientSecret = await store.get(`secret:${pow_nonce}`),
                ticket = null;
            if (pow_type === "cpu_target") {
                // Verify the new type
                ticket = verifyCpuTargetPoWAndGenerateTicket(
                    clientIp,
                    pow_nonce,
                    pow_solution,
                    suspicionFactor, // Pass the analog factor
                    clientSecret,
                );
                isValid = ticket !== null;            } else if (pow_type === "cpu_mem") {
                // Verify combined challenge
                const cpuTicket = verifyCpuTargetPoWAndGenerateTicket(
                    clientIp, pow_nonce, pow_solution_cpu, suspicionFactor, clientSecret
                );
                const minDifficulty = 16; // 16Mo
                const maxDifficulty = 48; // 48Mo
                const memActivationFactor = Math.max(0, (suspicionFactor - 0.25) / 0.75);
                const memDifficulty = Math.round(minDifficulty + memActivationFactor * (maxDifficulty - minDifficulty));

                const isMemValid = verifyMemoryPoW(pow_nonce, pow_solution_mem, memDifficulty, clientSecret);

                isValid = cpuTicket !== null && isMemValid;
                if (isValid) ticket = cpuTicket; // Reuse the ticket generated by the CPU verification
            } else if (pow_type === "tsp") {
                // Logic for TSP remains the same
                // ...
            }

            if (isValid) {
                // The secret has been used, delete it to prevent replay.
                if (clientSecret) {
                    await store.delete(`secret:${pow_nonce}`);
                }

                if (!ticket) {
                    // If the ticket has not already been generated (CPU case)
                    const expiry = Date.now() + 3600000; // 1 heure
                    const signature = crypto
                        .createHmac("sha256", getPowSecret())
                        .update(`${clientIp}:${expiry}`)
                        .digest("hex");
                    ticket = `${expiry}:${signature}`;
                }

                if (logger) {
                    logger({ type: 'challenge_solved', deviceId: cookies?.device_id, score: finalScore, challengeType: pow_type, timestamp: Date.now() });
                }

                return {
                  action: 'redirect',
                  path: path,
                  score: finalScore,
                  vector: suspicionVector,
                  cookie: {
                    name: 'pow_clearance',
                    value: ticket,
                    options: {
                      httpOnly: true,
                      secure: this.isProduction,
                      maxAge: 3600000,
                    }
                  }
                };
            }
        }

        // --- SELECTION AND SENDING OF THE APPROPRIATE CHALLENGE ---
        const nonce = crypto.randomBytes(16).toString("hex");
        const clientSecret = crypto.randomBytes(16).toString("hex");

        // Store the secret with a short TTL (e.g., 5 minutes)
        await store.set(`secret:${nonce}`, clientSecret, 300);

        // Associate the current challenge nonce with the device for trap URL verification later.
        if (deviceData) {
            deviceData.lastChallengeNonce = nonce;
            await store.set(`device:${cookies.device_id}`, deviceData);
        }

        if (logger) {
            logger({ type: 'challenge_issued', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now() });
        }

        // LEVEL 3: CAPTCHA (the highest)
        if (isSuspiciousHigh) {
            // ... logic for TSP/Captcha challenge
        }

        // UNIFIED CHALLENGE LOGIC for all suspicion levels (low, medium, high)
        if (isSuspicious) { // Couvre à la fois low et medium
            // Generate some trap URLs to embed in the challenge page.
            // These links are visually hidden but present in the DOM to trap bots.
            const trapUrls = Array.from({ length: 3 }, () => generateTrapUrl(nonce));
            const trapLinksHtml = trapUrls.map(url => `<a href="${url}" tabindex="-1">config</a>`).join(' ');


            const cpuChallengeDetails = generateCpuTargetChallenge(clientIp, nonce, suspicionFactor, path);

            // La difficulté mémoire démarre à 0 et augmente seulement après un certain seuil de suspicion.
            // Par exemple, elle ne commence à augmenter qu'à partir de 25% du chemin entre 'low' et 'high'.
            const memActivationFactor = Math.max(0, (suspicionFactor - 0.25) / 0.75);

            const minMemDifficulty = 0;   // Peut être 0 Mo !
            const maxMemDifficulty = 48;  // 48Mo pour les plus suspects
            const memDifficulty = Math.round(minMemDifficulty + memActivationFactor * (maxMemDifficulty - minMemDifficulty));

            // Always use the combined page, even if memory difficulty is 0 (it will be almost instant).
            const trapContainer = `<div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">${trapLinksHtml}</div>`;
            const page = generateCombinedPoWChallengePage(cpuChallengeDetails, memDifficulty, clientIp, clientSecret).replace('</body>', `${trapContainer}</body>`);
            return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 429, body: page };
        }
    }

    // Basic log for each non-static request that passed without a challenge
    if (logger) {
        logger({ type: 'request_passed', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now() });
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
    await store.set(`ip:${clientIp}`, ipProfile);

    const vector = await __internal.getSuspicionVector(requestContext, this.securityConfig); // Pass the config
    const { honeypotScore } = getHoneypotScore(requestContext, this.securityConfig.honeypot);
    const { requestPatternScore } = getRequestPatternScore(requestContext, (await store.get(`device:${requestContext.cookies?.device_id}`)), this.securityConfig.patterns);
    const score =
      vector.historyScore * (this.securityConfig.weights.historyScore || 0.3) +
      vector.rotationScore * (this.securityConfig.weights.rotationScore || 0.5) +
      vector.headerAnomalyScore * (this.securityConfig.weights.headerAnomalyScore || 0.1) +
      vector.inconsistencyScore * (this.securityConfig.weights.inconsistencyScore || 0.8) +
      honeypotScore * (this.securityConfig.weights.honeypotScore || 0) +      
      requestPatternScore * (this.securityConfig.weights.requestPatternScore || 0);

    if (score >= this.securityConfig.thresholds.high) return `suspicious_high:${clientIp}`;
    if (score >= this.securityConfig.thresholds.low) return `suspicious_medium:${clientIp}`; // Use medium for any suspicion
    if (score >= this.securityConfig.thresholds.medium) return `suspicious_medium:${clientIp}`;

    // If a new device_id was created, it's in the context.
    const newDeviceId = requestContext._newCookies?.find(c => c.name === 'device_id')?.value;
    const finalDeviceId = cookies?.device_id || newDeviceId || clientIp;

    return `device:${finalDeviceId}`;
  }
}

// --- Proof-of-Work Middleware (The Tollbooth) ---
export const powMiddleware = (securityConfig) => {
  const engine = new FingerprintEngine(securityConfig);

  if (securityConfig.autotuning) {
    startThresholdAutoTuning({
      securityConfig: securityConfig,
      ...securityConfig.autotuning,
    });
  }

  return async (req, res, next) => {
    const requestContext = {
      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
      path: req.path,
      cookies: req.cookies,
      query: req.query,
      body: req.body,
      headers: req.headers,
      isStatic: isStaticResource(req.path),
      // Add the newly required properties for full decoupling
      rawHeaders: req.rawHeaders,
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

      case 'challenge':
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
    getDeviceHash,
    getSuspicionVector,
    cyrb53, // Export for testing
    FingerprintBuilder, // Export for testing
    calculateTarget,
    FingerprintEngine, // Expose for advanced testing
    getRequestPatternScore, // Expose for testing
};

// --- THRESHOLD AUTO-TUNING SECTION ---

let autoTuningJobId = null;

/**
 * Executes a threshold optimization pass using collected traffic data.
 * @private
 * @param {object} securityConfig - The security configuration object to update.
 * @param {Array<object>} trafficData - The array containing traffic logs.
 * @param {number} minDataPoints - The minimum number of data points required to start optimization.
 */
function runThresholdOptimization(securityConfig, trafficData, minDataPoints) {
    if (trafficData.length < minDataPoints) {
        console.log(`[AutoTuning] Reporté : ${trafficData.length}/${minDataPoints} points de données.`);
        return;
    }
    console.log(`[AutoTuning] Démarrage du cycle d'optimisation avec ${trafficData.length} points de données.`);

    // Identify "bots" (those who received a challenge but never solved it)
    // and "humans" (those who passed the challenge or never received one).
    const solvedDevices = new Set(trafficData.filter(e => e.type === 'challenge_solved').map(e => e.deviceId));
    const historicalRequests = trafficData.map(log => {
        let isBot = false;
        if (log.type === 'challenge_issued' && !solvedDevices.has(log.deviceId)) {
            isBot = true; // Assumption: a challenge issued and not solved is a bot.
        }
        return { score: log.score, isBot };
    });

    // The "fitness" function evaluates the quality of a set of thresholds.
    // A lower score is better.
    const fitnessFunction = (solution) => {
        const [low, medium, high, velocityThreshold, burstThreshold, scrapeThreshold] = solution;
        // Constraints: thresholds must be ordered and within a reasonable range.
        if (low >= medium || medium >= high || low < 10 || high > 90) return Infinity;
        // Constraints for pattern thresholds
        if (velocityThreshold < 50 || velocityThreshold > burstThreshold || burstThreshold > scrapeThreshold) return Infinity;

        let falsePositives = 0; // Humans challenged unnecessarily.
        let falseNegatives = 0; // Undetected bots.

        for (const req of historicalRequests) {
            if (req.isBot) {
                if (req.score < low) falseNegatives++;
            } else { // Human
                if (req.score >= low) falsePositives++;
            }
        }
        // Penalize passing bots 2x more than inconvenienced humans.
        return (falsePositives * 1.0) + (falseNegatives * 2.0);
    };

    // Functions for the genetic algorithm.
    const createIndividual = () => [
        10 + Math.random() * 20, // low
        30 + Math.random() * 30, // medium
        60 + Math.random() * 30, // high
        100 + Math.random() * 150, // velocityThreshold (100-250ms)
        300 + Math.random() * 400, // burstThreshold (300-700ms)
        800 + Math.random() * 700, // scrapeThreshold (800-1500ms)
    ];
    const crossover = (p1, p2) => p1.map((val, i) => (val + p2[i]) / 2);
    const mutate = (s) => {
        const n = [...s];
        const i = Math.floor(Math.random() * n.length);
        // Adjust mutation range based on parameter
        const mutationRange = i < 3 ? 5 : 50;
        n[i] += (Math.random() - 0.5) * mutationRange;
        return n;
    };

    // Start optimization.
    const result = Optimization.geneticAlgorithm(createIndividual, fitnessFunction, crossover, mutate, {
        generations: 50,
        populationSize: 40
    });

    const [newLow, newMedium, newHigh, newVelocity, newBurst, newScrape] = result.solution;

    // Update the configuration live.
    // Ensure thresholds object exists
    if (!securityConfig.thresholds) securityConfig.thresholds = {};
    securityConfig.thresholds.low = Math.round(newLow);
    securityConfig.thresholds.medium = Math.round(newMedium);
    securityConfig.thresholds.high = Math.round(newHigh);

    // Update pattern detection parameters
    if (!securityConfig.patterns) securityConfig.patterns = {};
    securityConfig.patterns.velocityThreshold = Math.round(newVelocity);
    securityConfig.patterns.burstThreshold = Math.round(newBurst);
    securityConfig.patterns.scrapeThreshold = Math.round(newScrape);
    // Weights could also be optimized, but let's keep it to thresholds for now for simplicity.

    console.log("[AutoTuning] Nouveaux seuils optimisés appliqués :", securityConfig.thresholds);
    if (securityConfig.patterns) {
        console.log("[AutoTuning] Nouveaux paramètres de pattern appliqués :", securityConfig.patterns);
    }
}

/**
 * Starts the background process for auto-tuning security thresholds.
 * @export
 * @param {object} options - Configuration options for auto-tuning.
 * @param {object} options.securityConfig - The live security configuration object that will be mutated.
 * @param {Array<object>} options.trafficData - The array where the logger pushes traffic data.
 * @param {number} [options.interval=1800000] - The interval in milliseconds between each optimization cycle (default: 30 minutes).
 * @param {number} [options.minDataPoints=200] - The minimum number of requests to analyze before starting a cycle (default: 200).
 */
export function startThresholdAutoTuning(options) {
    if (autoTuningJobId) {
        console.warn("[AutoTuning] Le job est déjà en cours d'exécution.");
        return;
    }

    const {
        securityConfig,
        trafficData,
        interval = 1800000,
        minDataPoints = 200
    } = options;

    if (!securityConfig || !trafficData) {
        throw new Error("[AutoTuning] `securityConfig` et `trafficData` sont requis.");
    }

    console.log(`[AutoTuning] Job d'optimisation des seuils démarré. Prochain cycle dans ${interval / 60000} minutes.`);

    autoTuningJobId = setInterval(() => {
        runThresholdOptimization(securityConfig, trafficData, minDataPoints);
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
