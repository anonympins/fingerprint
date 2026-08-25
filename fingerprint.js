import crypto from "node:crypto";
import { BlockList } from "node:net";
import dns from "node:dns/promises";
import { Optimization } from "./library.js";
import { cyrb53, FingerprintBuilder } from "./fingerprint.builder.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
export { createRedisStore } from "./redis-store.js";
export { createMongoDbStore } from "./mongodb-store.js";

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
  try {
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const solverPath = join(__dirname, 'pow.solver.inline.js'); // Use the inline version
    return readFileSync(solverPath, 'utf-8');
  } catch (error) {
    console.warn('Could not load pow.solver.js for inlining, using fallback inline code');
    // Fallback inline code if file cannot be loaded
    return `(function(global){
        async function solveCpuTargetInline(clientIp, nonce, target, clientSecret, progressCallback){ const cpuTarget = typeof target === 'bigint' ? target : BigInt('0x' + target);
            const cpuTarget = BigInt(target);
            let cpuSolution = 0;
            const ipPart = clientIp || '';
            while(true){
                // When a clientSecret is used, the IP is omitted from the hash to make it independent of the network.
                const msg = clientSecret ? \`\${nonce}:\${cpuSolution}:\${clientSecret}\` : \`\${ipPart}:\${nonce}:\${cpuSolution}\`;
                const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(msg));
                const hashHex = Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
                if(BigInt('0x'+hashHex) < cpuTarget) break;
                cpuSolution++;
                if(cpuSolution % 100000 === 0) await new Promise(r=>setTimeout(r,0));
            }
            return cpuSolution;
        }
        async function solveMemory(seed, difficulty){
            const size = difficulty * 1024 * 1024;
            const buffer = new Uint32Array(size / 4);
            let h = new TextEncoder().encode(seed).reduce((acc,v)=>acc+v,0);
            for(let i=0;i<buffer.length;i++) buffer[i] = h = Math.imul(h^i,1597334677);
            let solution = 0;
            const iterations = size / 16;
            let addr = buffer.length > 0 ? buffer[0] % buffer.length : 0;
            for(let i=0;i<iterations;i++){
                addr = buffer[addr] % buffer.length;
                solution ^= addr;
            }
            return solution;
        }
        async function solveTsp(cities, targetMaxDistance){
            function distance(c1,c2){return Math.sqrt(Math.pow(c1.x-c2.x,2)+Math.pow(c1.y-c2.y,2));}
            function evaluatePathDistance(cities,path){
                let total=0;
                for(let i=0;i<path.length-1;i++) total+=distance(cities[path[i]],cities[path[i+1]]);
                total+=distance(cities[path[path.length-1]],cities[path[0]]);
                return total;
            }
            function solveTspNearestNeighbor(cities){
                const n=cities.length;
                if(n===0)return[];
                let path=[0];
                let visited=new Array(n).fill(false);
                visited[0]=true;
                for(let i=1;i<n;i++){
                    let nearest=-1, minDist=Infinity;
                    for(let j=0;j<n;j++){
                        if(!visited[j]){
                            const d=distance(cities[path[i-1]],cities[j]);
                            if(d<minDist){minDist=d;nearest=j;}
                        }
                    }
                    path.push(nearest);
                    visited[nearest]=true;
                }
                return path;
            }
            await new Promise(r=>setTimeout(r,10));
            const solutionPath=solveTspNearestNeighbor(cities);
            const solutionDistance=evaluatePathDistance(cities,solutionPath);
            return{path:solutionPath,distance:solutionDistance};
        }
        async function solveChallenge(challenge) {
            const { type, nonce, clientSecret, cpuTarget, memDifficulty, cities, clientIp, targetMaxDistance } = challenge;
            const solutions = {};

            switch (type) {
                case 'cpu_target':
                    solutions.cpu = await solveCpuTargetInline(clientIp, nonce, cpuTarget, clientSecret);
                    break;
                case 'cpu_mem':
                case 'cpu_mem_inline':
                    const memSeed = nonce + ":" + clientSecret;
                    const [cpuSol, memSol] = await Promise.all([
                        solveCpuTargetInline(clientIp, nonce, cpuTarget, clientSecret),
                        solveMemory(memSeed, memDifficulty)
                    ]);
                    solutions.cpu = cpuSol;
                    solutions.mem = memSol;
                    break;
                case 'tsp':
                    const tspResult = await solveTsp(cities, targetMaxDistance);
                    solutions.tsp = tspResult.path;
                    solutions.distance = tspResult.distance;
                    break;
                default:
                    throw new Error(\`Unknown challenge type: \${type}\`);
            }

            return solutions;
        }
        global.solveCpuChallengeInline=solveCpuTargetInline;
        global.solveMemoryChallenge=solveMemory;
        global.solveTspChallenge=solveTsp;
        global.solveChallenge=solveChallenge;
    })(typeof window!=='undefined'?window:global);`;
  }
};

/**
 * Calculates the JA3 fingerprint hash from the TLS Client Hello message.
 * JA3 is a more reliable way to identify client applications (e.g., a specific browser or a script)
 * based on the specifics of its TLS handshake.
 * @param {object} context - The request context, containing the raw request object.
 * @returns {string|null} The MD5 hash of the JA3 string, or null if it cannot be computed.
 */
function getJa3Hash(context) {
    // 1. Prefer the JA3 hash from a trusted reverse proxy (e.g., Nginx, Cloudflare).
    const ja3FromHeader = context.headers['x-ja3-hash'];
    if (ja3FromHeader) {
        return ja3FromHeader;
    }

    // 2. Fallback to calculating from the raw socket if available (requires Node.js to handle TLS).
    const clientHello = context.rawReq?.socket?.clientHello;
    if (!clientHello) {
        return null;
    }

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

        return crypto.createHash('md5').update(ja3String).digest('hex');
    } catch (e) {
        return null; // Could fail if clientHello structure is unexpected.
    }
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
    return cyrb53(headerKeys.join(','));
}
export function getDeviceHash(context) {
    // Prioritize the rich client-side fingerprint if provided.
    const clientFp = context.headers['x-device-fingerprint'];
    if (clientFp && typeof clientFp === 'string' && clientFp.includes('cvs:')) {
        return clientFp;
    }

    const srv = new FingerprintBuilder();

    // 1. SIGNAL FORT: User Agent (poids élevé)
    const ua = context.headers["user-agent"];
    if (ua) {
        srv.add("ua", ua);
        // Extraire des infos supplémentaires du UA
        const uaParts = parseUserAgent(ua);
        if (uaParts.browser) srv.add("browser", uaParts.browser);
        if (uaParts.os) srv.add("os_version", uaParts.os);
        if (uaParts.device) srv.add("device_type", uaParts.device);
    }

    // 2. SIGNAL FORT: JA3 TLS Fingerprint
    const ja3 = getJa3Hash(context);
    if (ja3) srv.add("ja3", ja3);

    // 3. SIGNAL MOYEN: Client Hints (modern browsers)
    if (context.headers["sec-ch-ua"]) {
        srv.add("ch_ua", context.headers["sec-ch-ua"]);
    }
    if (context.headers["sec-ch-ua-platform"]) {
        srv.add("ch_platform", context.headers["sec-ch-ua-platform"]);
    }
    if (context.headers["sec-ch-ua-mobile"]) {
        srv.add("ch_mobile", context.headers["sec-ch-ua-mobile"]);
    }
    if (context.headers["sec-ch-ua-model"]) {
        srv.add("ch_model", context.headers["sec-ch-ua-model"]);
    }
    if (context.headers["sec-ch-ua-arch"]) {
        srv.add("ch_arch", context.headers["sec-ch-ua-arch"]);
    }
    if (context.headers["sec-ch-ua-bitness"]) {
        srv.add("ch_bitness", context.headers["sec-ch-ua-bitness"]);
    }

    // 4. SIGNAL MOYEN: HTTP Version et protocole
    if (context.httpVersion) {
        srv.add("http_ver", context.httpVersion);
    }
    if (context.headers["upgrade-insecure-requests"]) {
        srv.add("upgrade", context.headers["upgrade-insecure-requests"]);
    }

    // 10. SIGNAL FORT: Ordonnancement des headers
    srv.add("h_ord", getHeaderSignature(context));

    // 11. SIGNAL AVANCÉ: Cookies (si disponible)
    if (context.cookies) {
        const cookieKeys = Object.keys(context.cookies).sort().join(',');
        srv.add("cookie_keys", cookieKeys);
    }

    // 12. SIGNAL AVANCÉ: Format de la requête
    if (context.rawHeaders) {
        // Vérifier des headers spécifiques qui indiquent le client
        const clientHeaders = ['x-requested-with', 'x-forwarded-for', 'x-real-ip', 'cf-connecting-ip'];
        clientHeaders.forEach(h => {
            if (context.headers[h]) {
                srv.add(h.replace(/-/g, '_'), context.headers[h]);
            }
        });
    }

    // 13. OPTIONNEL: IP (version simplifiée pour les réseaux partagés)
    // Ne pas inclure l'IP complète, mais un hash du réseau /24 ou /16
    // pour détecter les changements de réseau tout en protégeant la vie privée
    const ip = context.clientIp || context.headers['x-forwarded-for']?.split(',')[0]?.trim();
    if (ip && isPrivateIp(ip)) {
        // Pour les IP privées, on peut prendre le /24
        const networkHash = hashNetwork(ip, 24);
        srv.add("network", networkHash);
    }

    return srv.toString();
}

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
            const cities = ${citiesJson};
            const nonce = "${nonce}";
            const targetMaxDistance = ${targetMaxDistance};

            async function solve() {
              const result = await window.solveTspChallenge(cities, targetMaxDistance);
              
              if (result.distance <= targetMaxDistance) {
                window.location.href = "${path}" + "?pow_type=tsp&pow_nonce=" + nonce + "&pow_solution=" + JSON.stringify(result.path);
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
 * Calcule un score basé sur les métriques comportementales envoyées par le client.
 * @param {object} context - Le contexte de la requête, contenant les en-têtes.
 * @returns {{behaviorScore: number}}
 */
function getBehaviorScore(context) {
    const behaviorHeader = context.headers['x-behavior-metrics'];
    if (!behaviorHeader) {
        return { behaviorScore: 0 }; // Pas de données, pas de pénalité.
    }

    try {
        const metrics = JSON.parse(behaviorHeader);
        let score = 0;
        if (metrics.honeypotInteraction) score = 100; // Interaction avec un honeypot client = bot.
        if (metrics.mouseEntropy === 0 && metrics.keystrokeLatency === 0) score += 40; // Aucune interaction = suspect.
        return { behaviorScore: Math.min(100, score) };
    } catch (e) {
        return { behaviorScore: 10 }; // En-tête malformé = légèrement suspect.
    }
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
        velocityThreshold = 800, velocityWeight = 30,
        burstThreshold = 1500, burstWeight = 50,
        scrapeThreshold = 1000, scrapeWeight = 20, scrapeBurstWeight = 40,
        historySize = 10,
        decayFactor = 0.9,
        inactivityReset = 30000,
        // Nouveau paramètre pour la détection de séquences
        sequenceLength = 3, sequenceWeight = 60
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

        // 4. (NOUVEAU) Détection de séquences répétitives (ex: A -> B -> C -> A -> B -> C)
        if (history.length >= sequenceLength * 2) {
            const lastSequence = history.slice(-sequenceLength);
            const previousSequence = history.slice(-sequenceLength * 2, -sequenceLength);
            
            const isRepeating = lastSequence.every((req, i) => 
                req.path === previousSequence[i].path && req.queryString === previousSequence[i].queryString
            );
            if (isRepeating) score += sequenceWeight;
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
  return { ...behavioral, headerAnomalyScore, inconsistencyScore, behaviorScore, honeypotScore, requestPatternScore };
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
            const clientIp = "${clientIp}";
            const nonce = "${nonce}";
            const cpuTarget = BigInt("0x${target}");
            const solution = await window.solveCpuChallengeInline(clientIp, nonce, cpuTarget, null, (progress) => {
                // Optional progress callback
            });
            window.location.href = "${path}?pow_type=cpu_target&pow_nonce=${nonce}&pow_solution=" + solution;
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
    const solverCode = getPowSolverCode();
    return `
      <html><head><title>Advanced Security Check</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h1>Enhanced Verification... (Level 2)</h1>
        <p>Your activity requires an additional security check. This may take a few moments.</p>
        <div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div>
        <script>${solverCode}</script>
        <script>
          async function solve() {
            const nonce = "${nonce}";
            const path = "${path}";
            const clientSecret = "${clientSecret}";
            const clientIp = "${clientIp}";
            const cpuTarget = BigInt("0x${target}");
            const memDifficulty = ${memoryDifficulty};

            // --- CPU Challenge ---
            document.getElementById('loader').innerText = '⚙️ Performing CPU security calculation...';
            const cpuSolution = await window.solveCpuChallengeInline(clientIp, nonce, cpuTarget, clientSecret, (progress) => {
                // Optional progress callback
            });

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
  clientIp, // This parameter is crucial and must be the actual client IP
  ticketMaxAge, // NOUVEAU: Durée de validité du ticket configurable
  nonce,
  solution,
  clientSecret, // Le secret est maintenant requis
  target, // La cible est maintenant passée directement
) {
  const message = clientSecret
    ? `${nonce}:${solution}:${clientSecret}` // FIX: Ne pas inclure l'IP si un secret client est utilisé
    : `${clientIp}:${nonce}:${solution}`; // L'IP est utilisée uniquement pour les challenges sans secret (plus anciens/simples)
  const hash = crypto
    .createHash("sha256")
    .update(message)
    .digest("hex");
  const hashAsInt = BigInt("0x" + hash);

  if (hashAsInt < BigInt("0x" + target)) {
    // The comparison is direct with native BigInts
    // The proof is valid, generate the ticket
      const expiry = Date.now() + (ticketMaxAge || 3600000); // Utilise la durée passée ou un fallback.
      const signature = crypto
      .createHmac("sha256", getPowSecret())
      .update(`${clientIp}:${expiry}`)
      .digest("hex");
    return `${expiry}:${signature}`;
  }

  return null;
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
    return bestResult.solution;
}

/**
 * Vérifie si une chaîne de caractères contient des patterns d'injection connus.
 * @param {string} str - La chaîne à vérifier.
 * @returns {boolean} - True si un pattern malveillant est détecté.
 * @private
 */
function isMalicious(str) {
    if (typeof str !== 'string') return false;
    // Regex pour les injections SQL et NoSQL de base
    // Ajout de la détection des injections basées sur le temps (SLEEP, BENCHMARK, WAITFOR) et d'autres commandes dangereuses.
    const injectionRegex = /(\$ne|' *OR *'1'='1|['";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|SLEEP\(|BENCHMARK\(|WAITFOR DELAY)/i;
    // Regex pour les injections plus avancées
    const log4ShellRegex = /\$\{jndi:(ldap|rmi|dns):/i;
    const sstiRegex = /\{\{.*\}\}|\{%.*%\}/; // Détecte les syntaxes de type Jinja2, Twig, etc.
    const xxeRegex = /<!ENTITY\s+.*SYSTEM/i;
    const pathTraversalRegex = /(\.\.\/|\.\.\\)/;
    // Regex pour les injections de commandes.
    // Elle détecte deux cas :
    // 1. L'utilisation de backticks `` pour l'exécution de commandes.
    // 2. Des commandes dangereuses (comme rm, whoami) précédées par un séparateur de commande (;, &&, ||, |)
    //    pour éviter les faux positifs sur des phrases comme "A normal command like ls -la".
    const commandInjectionRegex = /`.*`|[\n;&|]\s*(ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b/i;

    return injectionRegex.test(str) || log4ShellRegex.test(str) || sstiRegex.test(str) || xxeRegex.test(str) || pathTraversalRegex.test(str) || commandInjectionRegex.test(str);
}

// --- Middleware Proof-of-Work (Le péage) ---
export { isMalicious };

export class FingerprintEngine {
  constructor(securityConfig) {
    const isProduction = process.env.NODE_ENV === 'production';
    this.securityConfig = securityConfig;
    this.isProduction = isProduction;
    this._allowlist = this._buildAllowlist();
    this.verbose = securityConfig.verbose || false;
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
            (suspicionVector.behaviorScore || 0) * (weights.behaviorScore || 0);

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
  _isIpInAllowlist(clientIp) {
    return this._allowlist.check(clientIp);
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

    // --- NOUVELLE LOGIQUE DE PRIORITÉ ---
    // Si une solution de challenge est soumise, on la traite en priorité absolue,
    // avant même de recalculer le score de suspicion.
    const { pow_type, pow_solution, pow_solution_cpu, pow_solution_mem } = query;
    if (pow_nonce && (pow_solution || (pow_solution_cpu && pow_solution_mem))) {
        this._log('Challenge solution submitted', { pow_type, pow_nonce });
        
        // On doit calculer le score de suspicion *avant* de valider le ticket,
        // car le TTL optimal en dépend.
        const preliminaryVector = await __internal.getSuspicionVector(requestContext, this.securityConfig);
        const preliminaryScore = this.calculateFinalScore(preliminaryVector);
        
        this._log('Preliminary suspicion vector calculated', { 
            vector: preliminaryVector, 
            score: preliminaryScore 
        });
        
        let isValid = false;
        const challengeContext = await store.get(`secret:${pow_nonce}`);
        let ticket = null;
        // Déclarer optimalTtl ici avec une valeur par défaut
        let optimalTtl = this.securityConfig.ticketMaxAge || 3600000;

        if (challengeContext) {
            optimalTtl = determineOptimalTicketTtl(preliminaryScore);
            this._log('Challenge context found, verifying solution', { optimalTtl });
            
            if (pow_type === "cpu_target") {
                // On passe la durée de vie du ticket configurée
                ticket = verifyCpuTargetPoWAndGenerateTicket(clientIp, optimalTtl, pow_nonce, pow_solution, challengeContext.clientSecret, challengeContext.cpuTarget);
                isValid = ticket !== null;
                this._log('CPU target challenge verification', { isValid });
            } else if (pow_type === "cpu_mem") {
                const cpuTicket = verifyCpuTargetPoWAndGenerateTicket(clientIp, optimalTtl, pow_nonce, pow_solution_cpu, challengeContext.clientSecret, challengeContext.cpuTarget);
                const isMemValid = verifyMemoryPoW(pow_nonce, pow_solution_mem, challengeContext.memDifficulty, challengeContext.clientSecret);
                isValid = cpuTicket !== null && isMemValid;
                if (isValid) ticket = cpuTicket; // Le ticket est le même, on le réutilise
                this._log('Combined CPU+Memory challenge verification', { 
                    cpuValid: cpuTicket !== null, 
                    memValid: isMemValid, 
                    isValid 
                });
            }
        } else {
            this._log('Challenge context not found or expired', { pow_nonce });
        }

        console.log({isValid})
        if (isValid) {
            // La solution est valide. On supprime le secret et on redirige.
            await store.delete(`secret:${pow_nonce}`);
            this._log('Challenge solution valid - issuing ticket', { ticketMaxAge: optimalTtl });

            if (logger) {
                logger({ type: 'challenge_solved', deviceId: cookies?.device_id, score: preliminaryScore, challengeType: pow_type, timestamp: Date.now() });
            }

            // NOUVELLE LOGIQUE DE REDIRECTION (plus robuste)
            // 1. On part du chemin original stocké, qui peut contenir des query params.
            const originalUrl = new URL(challengeContext?.originalPath || path, `http://${requestContext.headers.host || 'localhost'}`);

            console.log({originalUrl})
            // 2. On crée un nouvel objet de paramètres à partir de la requête entrante (qui contient les solutions ET les params originaux).
            const finalSearchParams = new URLSearchParams(requestContext.query);

            // 3. On supprime uniquement les paramètres liés au challenge.
            finalSearchParams.delete('pow_type');
            finalSearchParams.delete('pow_nonce');
            finalSearchParams.delete('pow_solution');
            finalSearchParams.delete('pow_solution_cpu');
            finalSearchParams.delete('pow_solution_mem');

            // 4. On reconstruit le chemin final.
            const finalQueryString = finalSearchParams.toString();
            const finalRedirectPath = finalQueryString ? `${originalUrl.pathname}?${finalQueryString}` : originalUrl.pathname;
            this._log('Redirecting to clean path', { finalRedirectPath });

            console.log({finalRedirectPath})
            return {
              action: 'redirect',
              path: finalRedirectPath,
              score: 0, // Le score n'est pas pertinent ici, on a passé le test.
              vector: { challenge_solved: 100 },
              cookie: {
                name: 'pow_clearance',
                value: ticket,
                options: {
                  httpOnly: true,
                  secure: this.isProduction, // Le maxAge est déjà inclus dans le ticket, mais on le met aussi sur le cookie
                  maxAge: optimalTtl,
                }
              }
            };
        }
        // Si la solution est INVALIDE, on ne fait rien ici. La requête continuera son cours normal,
        // sera recalculée comme suspecte, et probablement bloquée ou re-challengée, ce qui est le comportement souhaité.
        // On pourrait même ajouter une pénalité ici si on le voulait.
        this._log('Challenge solution invalid', { reason: challengeContext ? 'Invalid solution' : 'Nonce not found or expired' });
        
        if (logger && challengeContext) {
            logger({ type: 'challenge_failed', deviceId: cookies?.device_id, reason: 'Invalid PoW solution', timestamp: Date.now() });
        } else if (logger && !challengeContext) {
            logger({ type: 'challenge_failed', deviceId: cookies?.device_id, reason: 'Nonce not found or expired', timestamp: Date.now() });
        }
    }
    // --- FIN DE LA LOGIQUE DE PRIORITÉ ---

    // Resolve identity and check for persisted "condemned" status early.
    const { deviceId, deviceData, newCookie } = await resolveRequestIdentity(requestContext, this.securityConfig);
    const isNewDevice = !!newCookie;
    
    this._log('Identity resolved', { deviceId, isNewDevice, hasDeviceData: !!deviceData });

    if (deviceData?.condemned) {
        this._log('Device condemned - blocking request', { deviceId });
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Previously condemned', score: 100, vector: { honeypotScore: 100 } });
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

    // If the action is to block, we should still include the score and vector for logging/testing.
    if (isBlocked) {
      this._log('Request blocked - score exceeded block threshold', { finalScore, blockThreshold });
      if (onDeviceCompromised) {
        onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Score exceeded block threshold', score: finalScore, vector: suspicionVector });
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
            onDeviceCompromised({ deviceId: cookies?.device_id, clientIp, reason: 'Triggered signed honeypot trap URL', score: 100, vector: { honeypotScore: 100 } });
        }
        if (logger) {
            logger({ type: 'trap_triggered', deviceId: cookies?.device_id, score: 100, path: path, timestamp: Date.now() });
        }
        await store.set(`device:${cookies.device_id}`, deviceData); // No TTL for condemned status
        return { action: 'block', status: 404, score: 100, vector: { honeypotScore: 100 } };
    }

    if (isSuspicious && !isTicketValid(clientIp, powCookie)) {
        this._log('Suspicious request without valid ticket - issuing challenge', { finalScore, hasPowCookie: !!powCookie });
        
        // Honeypot: Direct probing of challenge endpoints is highly suspicious.
        // A legitimate user only hits these endpoints via the challenge page itself.
        // If we see a pow_nonce on a request that IS suspicious but has no valid ticket,
        // AND it's not a legitimate response to a challenge we issued, it's a probe.
        const isChallengeResponse = query.pow_solution || (query.pow_solution_cpu && query.pow_solution_mem);
        if (pow_nonce && !isChallengeResponse) {
            this._log('Honeypot probe detected - blocking request', { path, pow_nonce });
            if (logger) {
                logger({ type: 'honeypot_probe', deviceId: cookies?.device_id, score: finalScore, path: path, timestamp: Date.now() });
            }
            suspicionVector.honeypotScore = 100; // Bot is probing. Max penalty.
            // Recalculate the final score with the updated vector.
            const newFinalScore = this.calculateFinalScore(suspicionVector);
            return { action: 'block', status: 404, body: 'Forbidden', score: newFinalScore, vector: suspicionVector };
        }

        // --- SELECTION AND SENDING OF THE APPROPRIATE CHALLENGE ---
        const nonce = crypto.randomBytes(16).toString("hex");
        const clientSecret = crypto.randomBytes(16).toString("hex");

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

            this._log('Challenge parameters calculated', { 
                suspicionFactor, 
                memActivationFactor, 
                memDifficulty, 
                cpuTarget: cpuChallengeDetails.target 
            });

            // Store the entire challenge context with a short TTL (e.g., 5 minutes)
            await store.set(`secret:${nonce}`, {
                clientSecret,
                cpuTarget: cpuChallengeDetails.target,
                memDifficulty: memDifficulty,
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
                logger({ type: 'challenge_issued', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now() });
            }

            // Check if the request is an API request to return a JSON challenge
            const isApi = requestContext.rawReq && this.securityConfig.thresholds?.isApiRequest?.(requestContext.rawReq);

            if (isApi) {
                // For API clients, send a JSON response with challenge details.
                const challengePayload = {
                    challenge: {
                        type: 'cpu_mem',
                        nonce: nonce,
                        clientSecret: clientSecret, // The client needs this to solve the challenge
                        cpuTarget: cpuChallengeDetails.target,
                        memDifficulty: memDifficulty,
                    }
                };
                this._log('API challenge response generated', { challengePayload });
                return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: challengePayload };
            } else {
                // For browsers, send the HTML page.
                const trapContainer = `<div style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">${trapLinksHtml}</div>`;
                const page = generateCombinedPoWChallengePage(cpuChallengeDetails, memDifficulty, clientIp, clientSecret).replace('</body>', `${trapContainer}</body>`);
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

  if (securityConfig.autotuning) {
    startThresholdAutoTuning({
      securityConfig: securityConfig,
      ...securityConfig.autotuning,
    });
  }

  // Provide a default for isApiRequest if not specified by the user.
  // This makes API challenge handling work more seamlessly out-of-the-box.
  if (!securityConfig.thresholds?.isApiRequest) {
    if (!securityConfig.thresholds) securityConfig.thresholds = {};
    securityConfig.thresholds.isApiRequest = (req) => 
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
      isStatic: isStaticResource(req.path),
      // Pass the original request object for the isApiRequest function
      rawReq: req,
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
    getDeviceHash,
    getSuspicionVector,
    cyrb53, // Export for testing
    FingerprintBuilder, // Export for testing
    calculateTarget,
    determineOptimalTicketTtl,
    getRequestPatternScore, // Expose for testing
    getBehaviorScore, // Expose for testing
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

    // Classify historical requests with a confidence weight.
    const solvedDevices = new Set(trafficData.filter(e => e.type === 'challenge_solved').map(e => e.deviceId));
    const challengedDevices = new Set(trafficData.filter(e => e.type === 'challenge_issued').map(e => e.deviceId));

    const historicalRequests = trafficData.map(log => {
        // Assign a label ('bot' or 'human') and a confidence weight to each log entry.
        switch (log.type) {
            case 'honeypot_probe':
            case 'trap_triggered':
                return { score: log.score, label: 'bot', confidence: 10.0 }; // Very high confidence
            
            case 'challenge_issued':
                // A challenge issued to a device that never solved it is a strong bot signal.
                if (!solvedDevices.has(log.deviceId)) {
                    return { score: log.score, label: 'bot', confidence: 3.0 }; // High confidence
                }
                // If the challenge was eventually solved, this specific log is neutral.
                return null;

            case 'challenge_solved':
                return { score: log.score, label: 'human', confidence: 5.0 }; // High confidence

            case 'request_passed':
                // A passed request from a device that was never even challenged is likely a human.
                if (!challengedDevices.has(log.deviceId)) {
                    return { score: log.score, label: 'human', confidence: 0.5 }; // Low confidence
                }
                // If the device was challenged at some point, this log is ambiguous.
                return null;
            
            default:
                return null;
        }
    }).filter(Boolean); // Remove null entries

    // The "fitness" function evaluates the quality of a set of thresholds.
    // A lower score is better.
    const fitnessFunction = (solution) => {
        const [low, medium, high, velocityThreshold, burstThreshold, scrapeThreshold] = solution;
        if (low >= medium || medium >= high || low < 10 || high > 90) return Infinity;
        if (velocityThreshold < 50 || velocityThreshold > burstThreshold || burstThreshold > scrapeThreshold) return Infinity;

        let weightedFalsePositives = 0; // Humans challenged unnecessarily.
        let weightedFalseNegatives = 0; // Undetected bots.

        for (const req of historicalRequests) {
            if (req.label === 'bot') {
                if (req.score < low) weightedFalseNegatives += req.confidence;
            } else { // 'human'
                if (req.score >= low) weightedFalsePositives += req.confidence;
            }
        }
        // The penalty for false negatives is implicitly higher due to the higher confidence scores of bot signals.
        return weightedFalsePositives + weightedFalseNegatives;
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
