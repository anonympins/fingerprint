// C:/Dev/games.primals.net/src/utils/fingerprint.js
import crypto from "node:crypto";
import { Optimization } from "./library.js";

const POW_SECRET = process.env.POW_SECRET;

if (!POW_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('POW_SECRET environment variable is not set. This is required for production.');
} else if (!POW_SECRET) {
  console.warn('Warning: POW_SECRET environment variable not set. Using a default, insecure secret for development.');
}
/**
 * cyrb53 hash algorithm (fast with a low collision rate). Exported for reuse.
 */
export const cyrb53 = (str, seed = 0) => {
  let h1 = 0xdeadbeef ^ seed,
    h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
    ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 =
    Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^
    Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 =
    Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^
    Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};

/**
 * Class to build a composite fingerprint (Multi-Hash).
 * Output format: "grp1:hash1|grp2:hash2|grp3:hash3"
 */
export class FingerprintBuilder {
  constructor() {
    this.components = new Map();
  }

  /**
   * Adds a component to the global hash.
   * @param {string} group - The group name (e.g., 'hw', 'screen', 'geo')
   * @param {string|number|boolean} value - The raw value to be hashed
   */
  add(group, value) {
    if (value === undefined || value === null) return this;
    // Hash the value individually to anonymize it and reduce its size
    this.components.set(group, cyrb53(String(value)));
    return this;
  }

  /**
   * Generates the final signature string.
   * Sorts keys to ensure a deterministic order.
   */
  toString() {
    return Array.from(this.components.entries())
      .sort((a, b) => a[0].localeCompare(b[0])) // Tri alphabétique des clés
      .map(([key, hash]) => `${key}:${hash}`)
      .join("|");
  }

  /**
   * Compares two fingerprints and returns a similarity score (0 to 1).
   * Uses weights to give more importance to strong invariants (Canvas, GPU).
   * @param {string} fpString1 - Fingerprint A
   * @param {string} fpString2 - Fingerprint B
   */
  static compare(fpString1, fpString2) {
    if (!fpString1 || !fpString2) return 0;

    const parse = (str) => {
      const map = new Map();
      str.split("|").forEach((part) => {
        const [k, v] = part.split(":");
        if (k && v) map.set(k, v);
      });
      return map;
    };

    const map1 = parse(fpString1);
    const map2 = parse(fpString2);

    // "Veracity" weights (Entropy/Stability)
    const weights = {
      cvs: 4.0, // Canvas: Very high entropy (Unique rendering)
      gpu: 3.0, // GPU: High entropy (Specific hardware)
      hw: 1.5, // Hardware: Medium entropy
      scr: 1.0, // Screen: Medium
      geo: 0.5, // Geo: Low (VPN/Travel)
      os: 0.5, // OS: Low (Generic)
      bot: 0.0, // Bot: Informational
    };

    let weightedMatches = 0;
    let totalWeight = 0;

    const allKeys = new Set([...map1.keys(), ...map2.keys()]);

    allKeys.forEach((key) => {
      if (map1.has(key) && map2.has(key)) {
        const weight = weights[key] || 1.0;
        totalWeight += weight;

        if (map1.get(key) === map2.get(key)) {
          weightedMatches += weight;
        }
      }
    });

    return totalWeight === 0 ? 0 : weightedMatches / totalWeight;
  }
}

// Cache to avoid recalculating constants (Hardware, etc.)
let cachedBuilder = null;

/**
 * Generates the fingerprint of the current device.
 */
export const getDeviceFingerprint = () => {
  // NOTE: This is client-side code and should be in a separate file.
  // It will not work in a Node.js environment.
  // The presence of `window` and `document` confirms this.

  if (typeof window === "undefined") return "server-side";

  if (!cachedBuilder) {
    const nav = window.navigator;
    const screen = window.screen;

    cachedBuilder = new FingerprintBuilder();

    // 1. Hardware (Very stable): Cores, RAM, GPU (if available via canvas), Touch
    cachedBuilder.add(
      "hw",
      `${nav.hardwareConcurrency}_${nav.deviceMemory}_${nav.maxTouchPoints}`,
    );

    // 2. Geo/Locale (Stable except for travel/VPN): Timezone, Language
    cachedBuilder.add(
      "geo",
      `${Intl.DateTimeFormat().resolvedOptions().timeZone}_${nav.language}_${new Date().getTimezoneOffset()}`,
    );

    // 3. Screen (Stable except for monitor/zoom changes): Dimensions, ColorDepth
    // Note: We use availWidth/Height which excludes the taskbar, sometimes more unique
    cachedBuilder.add(
      "scr",
      `${screen.width}x${screen.height}_${screen.colorDepth}`,
    );

    // 4. Platform (Stable): OS, Engine
    cachedBuilder.add("os", nav.platform);

    // 5. Graphics (WebGL Vendor/Renderer) - Strong hardware invariant
    try {
      const canvas = document.createElement("canvas");
      const gl =
        canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
      if (gl) {
        const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
        if (debugInfo) {
          const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
          const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
          cachedBuilder.add("gpu", `${vendor}_${renderer}`);
        }
      }
    } catch (e) {}

    // 6. Canvas Fingerprinting (Rendering quirks) - Adds ~5-10% uniqueness
    // Exploits micro-differences in anti-aliasing and font rendering
    try {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      if (ctx) {
        canvas.width = 200;
        canvas.height = 50;
        ctx.textBaseline = "alphabetic";
        ctx.font = "14px 'Arial'";
        ctx.fillStyle = "#f60";
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069";
        ctx.fillText("Primals", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
        ctx.fillText("Primals", 4, 17);
        cachedBuilder.add("cvs", canvas.toDataURL());
      }
    } catch (e) {}

    // 7. Bot Detection (Hidden indicator)
    if (nav.webdriver) cachedBuilder.add("bot", "true");
  }

  // Return a copy to allow adding dynamic fields if needed without polluting the cache
  return cachedBuilder.toString();
};

/**
 * Generates a request signature including the context.
 * @param {object} payload
 */
export const generateRequestSignature = (payload = {}) => {
  const deviceFp = getDeviceFingerprint();

  // Create a temporary builder that inherits from deviceFp
  // Note: Here we keep it simple, just concatenating the payload hash
  const sortedPayload = Object.keys(payload)
    .sort()
    .map((k) => `${k}=${payload[k]}`)
    .join("&");
  const payloadHash = cyrb53(sortedPayload);

  return `${deviceFp}|req:${payloadHash}`;
};

/**
 * Generates an HMAC-SHA256 signature for combat data.
 * @param {object} payload - The data to sign (e.g., { opponentId, victory, damageDealt }).
 * @param {string} secret - The shared secret key.
 * @returns {Promise<string>} The hexadecimal signature.
 */
export const generateCombatSignature = async (payload, secret) => {
  // NOTE: This is client-side code using the Web Crypto API (`window.crypto`).
  // It should be moved to a client-side script file.

  // 1. Create a stable string from the payload.
  const sortedPayload = Object.keys(payload)
    .sort()
    .map((k) => `${k}=${payload[k]}`)
    .join("&");

  // 2. Use the Web Crypto API for HMAC
  const encoder = new TextEncoder();
  const key = await window.crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signatureBuffer = await window.crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(sortedPayload),
  );

  // 3. Convert the signature to a hexadecimal string.
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  const hexString = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hexString;
};

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
    .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
    .update(`${ip}:${expiry}`)
    .digest("hex");

  return `${expiry}:${signature}`;
};

/**
 * Verifies a memory PoW solution.
 * The server performs the same calculation to validate.
 */
export const verifyMemoryPoW = (nonce, solution, difficulty = 16) => {
  const size = difficulty * 1024 * 1024;
  const iterations = size / 16;
  const buffer = new Uint32Array(size / 4);
  let h = new TextEncoder().encode(nonce).reduce((acc, v) => acc + v, 0);
  for (let i = 0; i < buffer.length; i++) {
    buffer[i] = h = Math.imul(h ^ i, 1597334677);
  }
  let finalHash = 0;
  for (let i = 0; i < iterations; i++) {
    const addr = buffer[i % buffer.length] % buffer.length;
    finalHash ^= buffer[addr];
  }
  return finalHash === parseInt(solution, 10);
};
export const isTicketValid = (ip, ticket) => {
  if (!ticket) return false;
  const [expiry, sig] = ticket.split(":");
  if (!expiry || !sig || Date.now() > parseInt(expiry, 10)) return false;
  const expectedSig = crypto
    .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
    .update(`${ip}:${expiry}`)
    .digest("hex");

  // Use timingSafeEqual to prevent timing attacks
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig));
};

/**
 * Creates a stable hash based on device characteristics, independent of the IP.
 * This is our "level 2 fingerprint".
 * @param {object} req - The Express request object.
 * @returns {string} A hash representing the device.
 */
function getDeviceHash(req) {
  const srv = new FingerprintBuilder();
  srv.add("ua", req.headers["user-agent"]);
  if (req.headers["sec-ch-ua-platform"])
    srv.add("os", req.headers["sec-ch-ua-platform"]);
  if (req.headers["sec-ch-ua"]) srv.add("ch", req.headers["sec-ch-ua"]);
  return srv.toString(); // Returns the full fingerprint string for detailed comparison.
}

/**
 * Calculates suspicion indicators related to HTTP header anomalies.
 * @param {object} req - The Express request object.
 * @returns {{headerAnomalyScore: number}}
 */
function getHeaderAnomalies(req, consistencyScore) {
  // FIX: consistencyScore est maintenant passé
  let anomalyScore = 0;
  // Strong penalty if User-Agent is missing or very short (sign of a simple script)
  if (!req.headers["user-agent"] || req.headers["user-agent"].length < 10) {
    anomalyScore += 60;
  }
  // Penalty if Accept-Language header is missing
  if (!req.headers["accept-language"]) {
    anomalyScore += 25;
  }
  // Penalty for HTTP/1.0 requests, often used by old tools or bots
  if (req.httpVersion === "1.0") {
    anomalyScore += 15;
  }

  // NEW: Inconsistency score (stolen cookie?)
  // If the consistency score is low, add a massive penalty.
  // A score of 0.2 means a huge difference.
  const inconsistencyScore = Math.max(0, (1 - consistencyScore) * 200);

  return {
    headerAnomalyScore: Math.min(100, anomalyScore),
    inconsistencyScore: Math.min(100, inconsistencyScore),
  };
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
 * @param {object} req - The Express request object.
 * @param {object} res - The Express response object (to set the cookie).
 * @returns {Promise<{deviceId: string, deviceData: object, consistencyScore: number}>} 
 */
async function resolveRequestIdentity(req, res) {
  const existingDeviceId = req.cookies?.device_id;
  const currentDeviceHash = getDeviceHash(req);
  let deviceId = existingDeviceId;
  let consistencyScore = 1.0; // 1.0 = perfectly consistent
  let deviceData = null;

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

    // Set the cookie securely.
    res.cookie("device_id", deviceId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 31536000000, // 1 year
    });

    // Initialize tracking for this new device.
    deviceData = {
      initialDeviceHash: currentDeviceHash, // Anchor the initial fingerprint.
      ips: new Set(),
      lastUpdate: Date.now(),
      lastFpHash: currentDeviceHash,
      lastChangeTimestamp: 0,
      rapidChangeCount: 0,
    };
    // The write will happen in getSuspicionVector after all modifications.
  }

  return { deviceId, deviceData, consistencyScore };
}

/*
 * Calcule les indicateurs de suspicion liés au comportement de l'appareil (historique, rotation).
 * @param {object} req - The Express request object.
 * @param {object} deviceData - The device's activity data.
 * @returns {Promise<{historyScore: number, rotationScore: number}>}
 */
async function getBehavioralIndicators(req, deviceData) {
  const now = Date.now();
  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";

  // Get the IP type to modulate the score
  const ipProfile = (await store.get(`ip:${clientIp}`)) || { type: "residential" };
  const isSharedIp = ipProfile.type === "shared";

  const currentFpHash = getDeviceHash(req); // Use the device hash

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
 * @param {object} req - The Express request object.
 * @returns {Promise<{historyScore: number, rotationScore: number, headerAnomalyScore: number, inconsistencyScore: number}>}
 */
export const getSuspicionVector = async (req, res) => {
  const { deviceId, deviceData, consistencyScore } = await resolveRequestIdentity(req, res);

  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
  await store.set(`ip-device:${clientIp}`, deviceId); // Link the IP to the device

  // Periodically clean up device data
  if (Date.now() - deviceData.lastUpdate > 10 * 60 * 1000) { // 10 minutes
    deviceData.ips.clear();
    deviceData.rapidChangeCount = 0;
  }
  deviceData.lastUpdate = Date.now();

  const behavioral = await getBehavioralIndicators(req, deviceData);
  const anomalies = getHeaderAnomalies(req, consistencyScore);

  // Save the updated device state to the store
  await store.set(`device:${deviceId}`, deviceData);

  return { ...behavioral, ...anomalies };
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
export const identifyRequest = async (req, res) => {
  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
  const deviceId = req.cookies?.device_id;

  // --- Update IP reputation ---
  const ipProfile = (await store.get(`ip:${clientIp}`)) || {
    type: "residential",
    deviceIds: new Set(),
    statelessCount: 0,
    lastSeen: 0,
  };
  ipProfile.lastSeen = Date.now();
  if (deviceId) {
    ipProfile.deviceIds.add(deviceId);
  } else {
    // Improved anti-"Amnesiac Bot" logic
    ipProfile.statelessCount++;
  }

  // If an IP sees too many different devices, classify it as "shared".
  if (ipProfile.deviceIds.size > SHARED_IP_DEVICE_THRESHOLD) {
    ipProfile.type = "shared";
  }

  // If a residential IP makes too many requests without a cookie, it's a bot.
  // For a shared IP, we are more tolerant because new users are constantly arriving.
  const statelessLimit = ipProfile.type === "shared" ? 50 : 10;
  if (ipProfile.statelessCount > statelessLimit) {
    return `suspicious_high:${clientIp}`;
  }
  await store.set(`ip:${clientIp}`, ipProfile);

  // For compatibility with the rate-limiter, calculate a simple score.
  // The PoW will use the more complex weighted system.
  const vector = await getSuspicionVector(req, res);
  const score =
    vector.historyScore * 0.3 +
    vector.rotationScore * 0.5 +
    vector.headerAnomalyScore * 0.1 +
    vector.inconsistencyScore * 0.8; // Inconsistency is a very strong signal

  // Return a string for compatibility with rate limiters,
  // but based on suspicion thresholds.
  // NOTE: These thresholds are fixed here, but the PoW will use dynamic thresholds.
  if (score >= 75) {
    return `suspicious_high:${clientIp}`;
  }
  if (score >= 40) {
    return `suspicious_medium:${clientIp}`;
  }

  // For normal requests, return a hash of the fingerprint for rate limiting.
  // Use the device hash so the rate-limit follows the device, not the IP.
  const deviceIdForIp = await store.get(`ip-device:${clientIp}`);
  const finalDeviceId = deviceId || deviceIdForIp || clientIp;
  return `device:${finalDeviceId}`;
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
 * Verifies a PoW solution based on a target and generates a ticket.
 */
export function verifyCpuTargetPoWAndGenerateTicket(
  clientIp,
  nonce,
  solution,
  suspicionFactor,
) {
  const target = calculateTarget(suspicionFactor);
  const hash = crypto
    .createHash("sha256")
    .update(`${clientIp}:${nonce}:${solution}`)
    .digest("hex");
  const hashAsInt = BigInt("0x" + hash);

  if (hashAsInt < target) {
    // The comparison is direct with native BigInts
    // The proof is valid, generate the ticket
    const expiry = Date.now() + 3600000; // 1 heure
    const signature = crypto
      .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
      .update(`${clientIp}:${expiry}`)
      .digest("hex");
    return `${expiry}:${signature}`;
  }

  return null;
}

const staticExtensions =
    /\.(js|css|png|jpg|jpeg|gif|svg|mp3|webp|ico|woff|woff2|ttf|otf|map)$/i;
const isStaticResource = (req) => staticExtensions.test(req.path);

// --- Middleware Proof-of-Work (Le péage) ---
class FingerprintEngine {
  constructor(securityConfig) {
    const isProduction = process.env.NODE_ENV === 'production';
    this.securityConfig = securityConfig;
    this.isProduction = isProduction;
  }

  async processRequest(requestContext) {
    const { clientIp, path, cookies, query, isStatic } = requestContext;
    const { weights, thresholds, logger } = this.securityConfig;

    if (isStatic) {
      return { action: 'next' };
    }

    // We need to pass `req` and `res` to getSuspicionVector for cookie handling.
    // This is a remaining coupling point that could be refactored further.
    const suspicionVector = await __internal.getSuspicionVector(requestContext.rawReq, requestContext.rawRes);

    const finalScore =
      suspicionVector.historyScore * (weights.historyScore || 0) +
      suspicionVector.rotationScore * (weights.rotationScore || 0) +
      suspicionVector.headerAnomalyScore * (weights.headerAnomalyScore || 0) +
      suspicionVector.inconsistencyScore * (weights.inconsistencyScore || 0);

    const isSuspiciousHigh = finalScore >= thresholds.high;
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
    const { pow_type, pow_nonce, pow_solution } = query;

    // Basic log for each non-static request
    if (logger && !isSuspicious) {
        logger({ type: 'request_passed', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now() });
    }

    if (isSuspicious && !isTicketValid(clientIp, powCookie)) {
        // --- CHALLENGE SOLUTION HANDLING ---
        if (pow_nonce && pow_solution) {
            let isValid = false,
                ticket = null;
            if (pow_type === "cpu_target") {
                // Verify the new type
                ticket = verifyCpuTargetPoWAndGenerateTicket(
                    clientIp,
                    pow_nonce,
                    pow_solution,
                    suspicionFactor, // Pass the analog factor directly
                );
                isValid = ticket !== null;
            } else if (pow_type === "mem") {
                const minDifficulty = 16; // 16Mo
                const maxDifficulty = 48; // 48Mo
                const difficulty =
                    minDifficulty + suspicionFactor * (maxDifficulty - minDifficulty);
                isValid = verifyMemoryPoW(pow_nonce, pow_solution, difficulty);
            } else if (pow_type === "tsp") {
                // Logic for TSP remains the same
                // ...
            }

            if (isValid) {
                if (!ticket) {
                    // If the ticket has not already been generated (CPU case)
                    const expiry = Date.now() + 3600000; // 1 heure
                    const signature = crypto
                        .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
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

        if (logger) {
            logger({ type: 'challenge_issued', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now() });
        }

        // LEVEL 3: CAPTCHA (the highest)
        if (isSuspiciousHigh) {
            // ... logic for TSP/Captcha challenge
        }

        // LEVEL 2: Memory-Intensive PoW
        if (isSuspiciousMedium) {
            const minDifficulty = 16; // 16Mo
            const maxDifficulty = 48; // 48Mo
            const difficulty =
                minDifficulty + suspicionFactor * (maxDifficulty - minDifficulty);
            const page = generateMemoryPoWChallenge(clientIp, nonce, difficulty, path);
            return { action: 'challenge', status: 429, body: page };
        }

        if (isSuspicious) {
            const challengeDetails = generateCpuTargetChallenge(
                clientIp,
                nonce,
                suspicionFactor,
                path,
            );
            const challengePage = generateCpuTargetChallengePage(challengeDetails, clientIp);
            return { action: 'challenge', status: 429, body: challengePage };
        }
    }

    return { action: 'next' };
  }
}

// --- Proof-of-Work Middleware (The Tollbooth) ---
export const powMiddleware = (securityConfig) => {
  const engine = new FingerprintEngine(securityConfig);

  return async (req, res, next) => {
    const requestContext = {
      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
      path: req.path,
      cookies: req.cookies,
      query: req.query,
      headers: req.headers,
      isStatic: isStaticResource(req),
      // Pass raw req/res for now to handle cookie setting in resolveRequestIdentity
      rawReq: req,
      rawRes: res,
    };

    const decision = await engine.processRequest(requestContext);

    switch (decision.action) {
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
    getSuspicionVector,
    calculateTarget,
    FingerprintEngine, // Expose for advanced testing
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
        const [low, medium, high] = solution;
        // Constraints: thresholds must be ordered and within a reasonable range.
        if (low >= medium || medium >= high || low < 10 || high > 90) return Infinity;

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
    const createIndividual = () => [10 + Math.random() * 20, 30 + Math.random() * 30, 60 + Math.random() * 30];
    const crossover = (p1, p2) => [(p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2, (p1[2] + p2[2]) / 2];
    const mutate = (s) => {
        const n = [...s];
        const i = Math.floor(Math.random() * 3);
        n[i] += (Math.random() - 0.5) * 5;
        return n;
    };

    // Start optimization.
    const result = Optimization.geneticAlgorithm(createIndividual, fitnessFunction, crossover, mutate, {
        generations: 50,
        populationSize: 40
    });

    const [newLow, newMedium, newHigh] = result.solution;

    // Update the configuration live.
    securityConfig.thresholds = {
        low: Math.round(newLow),
        medium: Math.round(newMedium),
        high: Math.round(newHigh)
    };

    console.log("[AutoTuning] Nouveaux seuils optimisés appliqués :", securityConfig.thresholds);
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
