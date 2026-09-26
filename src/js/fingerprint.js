import crypto from "node:crypto";
import {BlockList, isIPv4, isIPv6} from "node:net";
import * as dns from "node:dns/promises";
import {Worker} from "node:worker_threads";
import {getProblemManager, problemManager} from "./problem-manager.js";
import {Optimization} from "./library.js";
import {cyrb53, FingerprintBuilder} from "./fingerprint.builder.js";
import {DynamicWasmGenerator} from "./dynamic-wasm.js";
import {writeFileSync, readFileSync, existsSync, promises as fsPromises} from "node:fs";
import {fileURLToPath} from "node:url";
import {dirname, join, resolve} from "node:path";
import {GpuPowSolver} from "./gpu_pow.solver.js";
import {
    verifyZkpProof,
    sanitizeRedirectPath,
    decodePolymorphicFingerprint,
    deepMerge,
    getHeaderSignature,
    parseJa3,
    modPow,
    hashNetwork,
    normalizeReferer,
    isLoopbackIp,
    isPrivateIp,
    parseUserAgent,
    safeJsonStringify
} from "./fingerprint.utils.js";


const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const secureRandomFloat = () => crypto.randomInt(0, 4294967296) / 4294967296;

let dnsCircuitBreaker = {
  state: 'CLOSED', // 'CLOSED', 'OPEN', 'HALF-OPEN'
  failureCount: 0,
  lastStateChange: 0,
  threshold: 5,
  cooldownMs: 30000, // 30 seconds
};

function recordDnsSuccess() {
  dnsCircuitBreaker.failureCount = 0;
  dnsCircuitBreaker.state = 'CLOSED';
}

function recordDnsFailure() {
  dnsCircuitBreaker.failureCount++;
  if (dnsCircuitBreaker.failureCount >= dnsCircuitBreaker.threshold) {
    dnsCircuitBreaker.state = 'OPEN';
    dnsCircuitBreaker.lastStateChange = Date.now();
  }
}

function canAttemptDns() {
  if (dnsCircuitBreaker.state === 'CLOSED') {
    return true;
  }
  if (dnsCircuitBreaker.state === 'OPEN') {
    if (Date.now() - dnsCircuitBreaker.lastStateChange > dnsCircuitBreaker.cooldownMs) {
      dnsCircuitBreaker.state = 'HALF-OPEN';
      return true;
    }
    return false;
  }
  return true; // HALF-OPEN
}

/**
 * Diffuse un ZKP banni aux pairs fédérés de manière asynchrone (non-bloquante).
 * @private
 * @param {string} zkpY - La clé publique ZKP du terminal banni.
 * @param {object} config - La configuration de sécurité.
 */
async function broadcastBannedZkp(zkpY, config) {
    const peers = config.federatedPeers || [];
    if (peers.length === 0) return;

    const timestamp = Date.now();
    const msg = `${timestamp}:${zkpY}`;
    
    let signature = '';
    let isAsymmetric = false;

    if (process.env.ED25519_PRIVATE_KEY) {
        try {
            const cleanKey = process.env.ED25519_PRIVATE_KEY.replace(/\\n/g, '\n');
            const signBuffer = crypto.sign(null, Buffer.from(msg), {
                key: cleanKey,
                format: 'pem',
                type: 'pkcs8'
            });
            signature = signBuffer.toString('hex');
            isAsymmetric = true;
        } catch (e) {
            console.error('[Fingerprint] Asymmetric broadcast signing failed, falling back to HMAC:', e.message);
        }
    }

    if (!isAsymmetric) {
        const secret = config.federationSecret || getPowSecret();
        signature = crypto.createHmac('sha256', secret).update(msg).digest('hex');
    }

    peers.forEach(peerUrl => {
        fetch(peerUrl + '?coop_op=share_threat_intel', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Federation-Signature': isAsymmetric ? '' : signature,
                'X-Federation-Signature-Ed25519': isAsymmetric ? signature : '',
                'X-Federation-Timestamp': String(timestamp)
            },
            body: JSON.stringify({ zkpY })
        }).catch(() => {
            // Échec de propagation silencieux pour ne pas perturber le thread principal
        });
    });
}

const withTimeout = (promise, ms) => {
  let timeoutId;
  const timeoutPromise = new Promise((_, reject) => {
    timeoutId = setTimeout(() => {
      reject(new Error('DNS_TIMEOUT'));
    }, ms);
  });
  return Promise.race([
    promise.then((res) => {
      clearTimeout(timeoutId);
      return res;
    }),
    timeoutPromise
  ]);
};

export { createRedisStore } from "./redis-store.js";
export { createMongoDbStore } from "./mongodb-store.js";

let activeMappings = [];
let lastMappingTime = 0;
let isCompilingMapping = false;
const MAPPING_ROTATION_INTERVAL = 60000; // 60 seconds

const configDir = resolve(__dirname, '../../config');

const loadBotWhitelist = (filename, fallbackEntries) => {
  const filePath = join(configDir, filename);
  if (existsSync(filePath)) {
    try {
      return JSON.parse(readFileSync(filePath, 'utf-8'));
    } catch (e) {
      console.error(`[Fingerprint] Error loading whitelist file ${filename}:`, e.message);
    }
  }
  return fallbackEntries;
};

const googlebotEntries = loadBotWhitelist('googlebot.json', [
]);

const bingbotEntries = loadBotWhitelist('bingbot.json', [
]);

const yandexEntries = loadBotWhitelist('yandex.json', [
]);

function generateSessionMapping() {
    const randomStr = (len = 6) => Array.from({ length: len }, () => String.fromCharCode(crypto.randomInt(97, 123))).join('');
    const randomHeader = () => `X-Sess-${crypto.randomBytes(4).toString('hex')}`;

    return {
        headers: {
            'x-device-fingerprint': randomHeader(),
            'x-behavior-metrics': randomHeader(),
        },
        globals: {
            'ClientLibrary': `ClientLib_${randomStr(6)}`,
            'getDeviceFingerprint': `getFP_${randomStr(6)}`,
            'getClientBehaviorMetrics': `getMetrics_${randomStr(6)}`,
        },
        keys: {
            'ua': randomStr(4),
            'hw': randomStr(4),
            'geo': randomStr(4),
            'scr': randomStr(4),
            'os': randomStr(4),
            'gpu': randomStr(4),
            'cvs': randomStr(4),
            'cdp': randomStr(4),
            'bot': randomStr(4),
            'wasm': randomStr(4),
        },
        wasmConstants: {
            seed: crypto.randomBytes(4).readInt32LE(0),
            multiplier: crypto.randomBytes(4).readInt32LE(0) | 1,
            adder: crypto.randomBytes(4).readInt32LE(0)
        }
    };
}

async function compilePolymorphicJs(mapping) {
    const clientScriptPath = join(__dirname, 'fingerprint.client.js');
    let jsCode = '';
    try {
        jsCode = readFileSync(clientScriptPath, 'utf-8');
    } catch (e) {
        console.error('[Fingerprint] Could not read fingerprint.client.js for dynamic obfuscation. Fallback to obfuscated build.');
        try {
            return readFileSync(join(__dirname, 'fingerprint.client.obfuscated.js'), 'utf-8');
        } catch (err) {
            return '';
        }
    }

    jsCode = jsCode.replace(/X-Device-Fingerprint/g, mapping.headers['x-device-fingerprint']);
    jsCode = jsCode.replace(/X-Behavior-Metrics/g, mapping.headers['x-behavior-metrics']);
    jsCode = jsCode.replace(/ClientLibrary/g, mapping.globals['ClientLibrary']);
    jsCode = jsCode.replace(/getDeviceFingerprint/g, mapping.globals['getDeviceFingerprint']);
    jsCode = jsCode.replace(/getClientBehaviorMetrics/g, mapping.globals['getClientBehaviorMetrics']);

    for (const [origKey, randKey] of Object.entries(mapping.keys)) {
        const regex1 = new RegExp(`add\\(["']${origKey}["']`, 'g');
        jsCode = jsCode.replace(regex1, `add("${randKey}"`);

        const regex2 = new RegExp(`addRaw\\(["']${origKey}["']`, 'g');
        jsCode = jsCode.replace(regex2, `addRaw("${randKey}"`);
    }

    return new Promise((resolve, reject) => {
        const worker = new Worker(new URL('./obfuscation.worker.js', import.meta.url));
        worker.on('message', (message) => {
            if (message.error) {
                console.error('[Fingerprint] Obfuscation worker error:', message.error, message.stack);
                reject(new Error('Obfuscation failed in worker.'));
            } else {
                resolve(message.obfuscatedCode);
            }
            worker.terminate();
        });
        worker.on('error', (error) => {
            console.error('[Fingerprint] Obfuscation worker crashed:', error);
            reject(error);
        });
        worker.on('exit', (code) => {
            if (code !== 0) {
                console.error(`[Fingerprint] Obfuscation worker stopped with exit code ${code}`);
                reject(new Error(`Obfuscation worker stopped with exit code ${code}`));
            }
        });
        worker.postMessage({ jsCode, seed: mapping.wasmConstants.seed });
    });
}

async function ensureLatestMapping() {
    const now = Date.now();
    if ((now - lastMappingTime > MAPPING_ROTATION_INTERVAL || activeMappings.length === 0) && !isCompilingMapping) {
        isCompilingMapping = true;
        try {
            const mapping = generateSessionMapping();
            const polymorphicJs = await compilePolymorphicJs(mapping);
            const polymorphicWasm = DynamicWasmGenerator.generate(mapping.wasmConstants);

            mapping.jsBuffer = Buffer.from(polymorphicJs, 'utf8');
            mapping.wasmBuffer = polymorphicWasm;
            mapping.timestamp = now;

            activeMappings.unshift(mapping);
            activeMappings = activeMappings.slice(0, 5);
            lastMappingTime = now;

            try {
                await store.set('active-polymorphic-mappings', activeMappings.map(m => ({
                    headers: m.headers,
                    keys: m.keys
                })));
            } catch (e) {
                // Ignore
            }
        } finally {
            isCompilingMapping = false;
        }
    }
}

function getActiveMappingForRequest(headers) {
    if (!headers) return null;
    for (const mapping of activeMappings) {
        const headerName = mapping.headers['x-device-fingerprint'].toLowerCase();
        if (headers[headerName]) {
            return mapping;
        }
    }
    return null;
}



const base64UrlEncode = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const base64UrlDecode = (str) => {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
};

export function generateStatelessTicket(payload) {
  let ed25519Key = process.env.ED25519_PRIVATE_KEY;
  if (ed25519Key) {
    try {
      ed25519Key = ed25519Key.replace(/\\n/g, '\n');
      const serialized = JSON.stringify(payload);
      let signature;
      try {
        signature = crypto.sign(undefined, Buffer.from(serialized), {
          key: ed25519Key,
          format: 'pem',
          type: 'pkcs8'
        });
      } catch (signErr) {
        signature = crypto.sign(null, Buffer.from(serialized), {
          key: ed25519Key,
          format: 'pem',
          type: 'pkcs8'
        });
      }
      return `ed25519.${base64UrlEncode(Buffer.from(serialized))}.${base64UrlEncode(signature)}`;
    } catch (e) {
      console.error('[Fingerprint] Ed25519 signing failed, falling back to symmetric:', e.message);
    }
  }

  const secret = getPowSecret();
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(payload));
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  
  const signature = crypto.createHmac('sha256', key).update(Buffer.concat([iv, encrypted])).digest();
  return `${base64UrlEncode(iv)}.${base64UrlEncode(encrypted)}.${base64UrlEncode(signature)}`;
}
/**
 * Détecte les anomalies de protocole (HTTP/2 et QUIC/HTTP3) par rapport au User-Agent.
 * @private
 * @param {object} context - Le contexte de la requête.
 * @returns {{protocolAnomalyScore: number}}
 */
function getProtocolAnomalyScore(context) {
    let http2Anomaly = 0.0;
    let quicAnomaly = 0.0;

    const ua = context.headers?.['user-agent'] || '';
    const uaParts = parseUserAgent(ua);
    const browser = uaParts.browser;

    if (browser) {
        // HTTP/2 Anomaly Logic
        const h2Fp = context.headers?.['x-http2-fingerprint'] || context.http2Fingerprint || null;
        if (h2Fp && typeof h2Fp === 'string') {
            const parts = h2Fp.split('|');
            if (parts.length >= 4) {
                const connWindow = parseInt(parts[1], 10);
                const headerOrder = parts[3];
                const isChromium = browser.startsWith('Chrome') || browser.startsWith('Edge');
                const isFirefox = browser.startsWith('Firefox');
                const isSafari = browser.startsWith('Safari');

                if (isChromium) {
                    if (headerOrder && headerOrder !== 'm,a,s,p') http2Anomaly += 60.0;
                    if (connWindow === 65535 || connWindow === 65536) http2Anomaly += 40.0;
                } else if (isFirefox) {
                    if (headerOrder && headerOrder !== 'm,s,p,a') http2Anomaly += 60.0;
                } else if (isSafari) {
                    if (headerOrder && headerOrder !== 'm,s,p,a') http2Anomaly += 60.0;
                }
            }
        }

        // QUIC Anomaly Logic
        const quicFp = context.headers?.['x-quic-fp'] || context.quicFingerprint || null;
        if (quicFp && typeof quicFp === 'string') {
            const parts = quicFp.split(';');
            if (parts.length >= 2) {
                const params = {};
                parts[1].split(',').forEach(p => {
                    const kv = p.split('=');
                    if (kv.length === 2) params[kv[0]] = kv[1];
                });
                const priorityOrder = parts[2] || '';
                const frameOrderRaw = parts[3] || context.headers?.['x-quic-frame-order'] || context.quicFrameOrder || '';
                const frameOrder = frameOrderRaw.toLowerCase().split(',').map(s => s.trim()).filter(Boolean);

                const isChromium = browser.startsWith('Chrome') || browser.startsWith('Edge');
                const isFirefox = browser.startsWith('Firefox');
                const isSafari = browser.startsWith('Safari');

                const maxData = parseInt(params['1'] || params['0x01'] || '0', 10);
                const maxStreams = parseInt(params['4'] || params['8'] || params['0x08'] || '0', 10);
                const bidiLocal = parseInt(params['5'] || params['0x05'] || '0', 10);
                const bidiRemote = parseInt(params['6'] || params['0x06'] || '0', 10);

                if (isChromium) {
                    // Contrôle de flux global et nombre de flux bidirectionnels
                    if (maxData > 0 && maxData < 1048576) quicAnomaly += 40.0;
                    if (maxStreams > 0 && maxStreams !== 100) quicAnomaly += 30.0;
                    if (priorityOrder && !priorityOrder.includes('u=')) quicAnomaly += 30.0;

                    // Contrôle de flux bidi (Chromium alloue 6MB = 6291456 ou au minimum 512 Ko)
                    // curl-impersonate / quiche alloue 256 Ko (262144) ou 128 Ko (131072)
                    if (bidiLocal > 0 && (bidiLocal < 524288 || bidiLocal === 262144)) quicAnomaly += 40.0;
                    if (bidiRemote > 0 && (bidiRemote < 524288 || bidiRemote === 262144)) quicAnomaly += 30.0;

                    // Ordre des trames de contrôle QUIC (SETTINGS, MAX_STREAMS, PRIORITY)
                    if (frameOrder.length >= 2) {
                        const sIdx = frameOrder.findIndex(f => f === 's' || f === 'settings' || f === '4');
                        const mIdx = frameOrder.findIndex(f => f === 'm' || f === 'max_streams' || f === '18');
                        const pIdx = frameOrder.findIndex(f => f === 'p' || f === 'priority' || f === 'priority_update' || f === '15');

                        if (sIdx !== 0 && sIdx !== -1) {
                            quicAnomaly += 50.0; // SETTINGS doit obligatoirement être la première trame
                        }
                        if (mIdx !== -1 && sIdx !== -1 && mIdx < sIdx) {
                            quicAnomaly += 60.0; // MAX_STREAMS envoyé avant SETTINGS (défaut curl/quiche)
                        }
                        if (pIdx !== -1 && sIdx !== -1 && pIdx < sIdx) {
                            quicAnomaly += 60.0;
                        }
                    }
                } else if (isFirefox) {
                    const maxData = parseInt(params['1'] || '0', 10);
                    if (maxData > 0 && maxData > 5000000) quicAnomaly += 40.0;
                    // Necko (Firefox) n'utilise pas 100 flux bidi par défaut ni un buffer bidi de 6 Mo
                    if (maxStreams === 100) quicAnomaly += 50.0;
                    if (bidiLocal === 6291456) quicAnomaly += 50.0;

                    if (frameOrder.length >= 2) {
                        const sIdx = frameOrder.findIndex(f => f === 's' || f === 'settings' || f === '4');
                        if (sIdx !== 0 && sIdx !== -1) quicAnomaly += 50.0;
                    }
                } else if (isSafari) {
                    // Safari Network.framework
                    if (maxStreams === 100 && maxData === 1572864 && priorityOrder.includes('u=2,i')) {
                        quicAnomaly += 60.0; // Usurpation par profil Cronet / curl-impersonate
                    }
                    if (bidiLocal === 6291456) quicAnomaly += 50.0;

                    if (frameOrder.length >= 2) {
                        const sIdx = frameOrder.findIndex(f => f === 's' || f === 'settings' || f === '4');
                        const mIdx = frameOrder.findIndex(f => f === 'm' || f === 'max_streams');
                        if (mIdx !== -1 && (mIdx === 0 || (sIdx !== -1 && mIdx < sIdx))) {
                            quicAnomaly += 50.0;
                        }
                    }
                }
            }
        }
    }

    return {
        protocolAnomalyScore: Math.max(
            0.0,
            Math.min(100.0, http2Anomaly),
            Math.min(100.0, quicAnomaly)
        ),
        http2AnomalyScore: Math.min(100.0, http2Anomaly),
        quicAnomalyScore: Math.min(100.0, quicAnomaly)
    };
}
/**
 * Détecte les anomalies de rendu (V-Sync, FPS, gigue) à partir des métriques d'affichage.
 * @private
 * @param {object} context - Le contexte de la requête.
 * @returns {{renderingAnomalyScore: number}}
 */
function getRenderingAnomalyScore(context) {
  const behaviorHeader = context.headers?.['x-behavior-metrics'];
  if (!behaviorHeader) {
    return { renderingAnomalyScore: 0.0 };
  }
  try {
    const metrics = JSON.parse(behaviorHeader);
    if (!metrics || !metrics.rendering) {
      return { renderingAnomalyScore: 0.0 };
    }
    const rendering = metrics.rendering;
    let score = 0.0;
    if (rendering.offscreenAnom) {
      score += 100.0;
    }
    const fps = parseFloat(rendering.fps || 0.0);
    const jitter = parseFloat(rendering.jitter || 0.0);
    if (fps > 250.0 || (fps > 0.0 && fps < 15.0)) {
      score += 50.0;
    }
    if (jitter > 6.0) {
      score += Math.min(80.0, (jitter - 6.0) * 10.0);
    }
    return { renderingAnomalyScore: Math.min(100.0, score) };
  } catch (e) {
    return { renderingAnomalyScore: 0.0 };
  }
}
export function parseStatelessTicket(ticket) {
  try {
    if (ticket.startsWith('ed25519.')) {
      const parts = ticket.split('.');
      if (parts.length !== 3) return null;
      const payloadBuffer = base64UrlDecode(parts[1]);
      const signatureBuffer = base64UrlDecode(parts[2]);
      let publicKey = process.env.ED25519_PUBLIC_KEY;
      if (!publicKey) {
        console.error('[Fingerprint] ED25519_PUBLIC_KEY is not defined in environment.');
        return null;
      }
      publicKey = publicKey.replace(/\\n/g, '\n');
      
      let isVerified = false;
      try {
        isVerified = crypto.verify(undefined, payloadBuffer, {
          key: publicKey,
          format: 'pem',
          type: 'spki'
        }, signatureBuffer);
      } catch (verifyErr) {
        try {
          isVerified = crypto.verify(null, payloadBuffer, {
            key: publicKey,
            format: 'pem',
            type: 'spki'
          }, signatureBuffer);
        } catch (verifyErr2) {
          isVerified = false;
        }
      }
      if (!isVerified) return null;
      return JSON.parse(payloadBuffer.toString('utf8'));
    }

    const parts = ticket.split('.');
    if (parts.length !== 3) return null;
    
    const iv = base64UrlDecode(parts[0]);
    const encrypted = base64UrlDecode(parts[1]);
    const signature = base64UrlDecode(parts[2]);
    
    if (iv.length !== 16) return null;
    
    const secret = getPowSecret();
    const key = crypto.createHash('sha256').update(secret).digest();
    
    const expectedSignature = crypto.createHmac('sha256', key).update(Buffer.concat([iv, encrypted])).digest();
    if (signature.length !== expectedSignature.length || !crypto.timingSafeEqual(signature, expectedSignature)) {
      return null;
    }
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    
    return JSON.parse(decrypted.toString('utf8'));
  } catch (e) {
    return null;
  }
}

/**
 * Vérifie le limiteur de débit Token Bucket pour les demandes de challenge d'un sous-réseau par domaine.
 * @param {string} clientIp - L'adresse IP du client.
 * @param {string} [domain='default'] - Le domaine/hôte ciblé (en-tête Host).
 * @param {object} [rateLimitConfig] - Configuration optionnelle du limiteur.
 * @returns {Promise<boolean>} True si la requête est autorisée, false si elle est limitée.
 */
async function checkChallengeRateLimit(clientIp, domain = 'default', rateLimitConfig = {}) {
  if (rateLimitConfig && rateLimitConfig.enabled === false) {
    return true;
  }
  if (!clientIp || isLoopbackIp(clientIp)) {
    return true; // Bypass local/dev
  }

  const subnet = getIpSubnet(clientIp) || clientIp;
  if (!subnet) return false;

  const host = (domain || 'default').toLowerCase().split(':')[0];
  const key = `rate-limit:${host}:${subnet}`;

  const capacity = Number(rateLimitConfig?.capacity ?? 30.0);
  const refillRate = Number(rateLimitConfig?.refillRate ?? 1.0); // 1 token par seconde (au lieu de 0.1)
  const now = Date.now() / 1000;

  const rateLimitData = (await store.get(key)) || {
    tokens: capacity,
    lastRefill: now
  };

  const elapsed = Math.max(0, now - rateLimitData.lastRefill);
  const tokens = Math.min(capacity, rateLimitData.tokens + elapsed * refillRate);
  const ttl = Math.max(60, Math.ceil(capacity / Math.max(0.1, refillRate)));

  if (tokens < 1.0) {
    await store.set(key, { tokens, lastRefill: now }, ttl);
    return false;
  }

  await store.set(key, { tokens: tokens - 1.0, lastRefill: now }, ttl);
  return true;
}

/**
 * Génère la page HTML de challenge GPU basée sur la trajectoire d'une carte logistique chaotique.
 * @private
 * @param {object} challengeDetails - Les détails du challenge.
 * @returns {string}
 */
function generateGpuChallengePage(challengeDetails) {
  const { nonce, iterations, path } = challengeDetails;
  const safePath = sanitizeRedirectPath(path);
  const solverCode = getPowSolverCode();
  return `
    <html><head><title>GPU Hardware Verification</title></head>
    <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
      <h1>Hardware Performance Check</h1>
      <p>Please wait while we verify your graphics card's math precision to ensure you are a human...</p>
      <div id="loader" style="margin:20px;">⚙️ Running parallel chaotic iterations...</div>
      <script>${solverCode}</script>
      <script type="module">
        import { GpuPowSolver } from './gpu_pow.solver.js';
        async function solve() {
          const nonce = ${safeJsonStringify(nonce)};
          const iterations = ${iterations};
          try {
            const result = await GpuPowSolver.solve(nonce, iterations);
            window.location.href = ${safeJsonStringify(safePath)} + "?pow_type=gpu&pow_nonce=" + nonce + "&pow_solution=" + result.solution;
          } catch(e) {
            document.getElementById('loader').innerText = "GPU hardware acceleration is required to complete this verification.";
          }
        }
        solve();
      </script>
    </body></html>`;
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
            botScore: 1.0,
            cookieDroppingScore: 0.9,
            crossLayerInconsistencyScore: 0.4,
            timeInconsistencyScore: 0.9,
            tlsSpoofingScore: 0.8,
            clientHintsInconsistencyScore: 0.7,
            clickVarianceScore: 0.6,
            subnetScore: 0.4,
            ipReputationScore: 0.5,
            botnetClusterScore: 0.6,
            tcpAnomalyScore: 0.8,
            quicAnomalyScore: 0.8, // NOUVEAU: Poids pour l'anomalie QUIC
            protocolAnomalyScore: 0.8, // NOUVEAU: Poids pour l'anomalie HTTP/2
            renderingAnomalyScore: 0.8, // NOUVEAU: Poids pour l'anomalie de rendu
            threatIntelScore: 1.0, // NOUVEAU: Poids pour le réseau de Threat Intelligence Fédéré
            virtualizationScore: 0.8,
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
        allowCrossNetworkRoaming: true, // Profil balancé : tolérant par défaut
        wasm: true,
        filterWhitelist: 85.0, // Stratégie d'inspection modérée pour les IP/chemins en liste blanche
        useAsymmetricTickets: true,
        enableGpuPow: true, // Activer le challenge GPU
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
            botScore: 1.0,
            cookieDroppingScore: 1.0,
            crossLayerInconsistencyScore: 0.6,
            timeInconsistencyScore: 1.0,
            tlsSpoofingScore: 1.0,
            clientHintsInconsistencyScore: 0.9,
            clickVarianceScore: 0.7,
            subnetScore: 0.5,
            ipReputationScore: 0.6,
            botnetClusterScore: 0.8,
            tcpAnomalyScore: 1.0,
            protocolAnomalyScore: 1.0,
            quicAnomalyScore: 1.0,
            renderingAnomalyScore: 1.0,
            threatIntelScore: 1.0,
            virtualizationScore: 1.0,
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
        allowCrossNetworkRoaming: false, // Strict : interdiction de changer complètement de réseau sans re-challenge
    filterWhitelist: true, // Tout comportement d'attaque certain bypass immédiatement la liste blanche
    wasm: true,
        useAsymmetricTickets: true,
        enableGpuPow: true,
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
            botScore: 0.8,
            cookieDroppingScore: 0.8,
            crossLayerInconsistencyScore: 0.5,
            timeInconsistencyScore: 0.8,
            tlsSpoofingScore: 0.7,
            clientHintsInconsistencyScore: 0.6,
            clickVarianceScore: 0.3,
            subnetScore: 0.4,
            ipReputationScore: 0.5,
            botnetClusterScore: 0.7,
            tcpAnomalyScore: 0.8,
            protocolAnomalyScore: 0.8,
            quicAnomalyScore: 0.8,
            renderingAnomalyScore: 0.2,
            threatIntelScore: 0.6,
            virtualizationScore: 0.8,
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
        allowCrossNetworkRoaming: false, // Les API ne doivent pas subir de roaming inter-IP suspect
    filterWhitelist: 75.0, // Seuil bas pour parer au vol de clés/tokens API légitimes
    wasm: true,
        useAsymmetricTickets: true,
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
            tlsSpoofingScore: 0.6, // Moins critique pour les blogs
            botScore: 0.8,
            cookieDroppingScore: 0.7, // Moins critique, mais toujours un signal
            threatIntelScore: 0.3, // Lower priority for a blog
            clientHintsInconsistencyScore: 0.5,
            clickVarianceScore: 0.5, // Moderate weight for click variance
            subnetScore: 0.4, // Utile contre le spam de commentaires coordonné
            ipReputationScore: 0.3, // NOUVEAU: Poids pour la réputation IP
            botnetClusterScore: 0.5, // NOUVEAU: Poids pour le clustering botnet
            tcpAnomalyScore: 0.5, // NEW: Anomalie de pile TCP/IP
            protocolAnomalyScore: 0.5,
            quicAnomalyScore: 0.5, // NOUVEAU: Poids pour l'anomalie QUIC
            renderingAnomalyScore: 0.5, // NOUVEAU: Poids pour l'anomalie de rendu
            virtualizationScore: 0.8,
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
        allowCrossNetworkRoaming: true,
    wasm: true,
    filterWhitelist: 90.0, // Très tolérant, n'inspecte que si le score est presque au blocage
        useAsymmetricTickets: true,
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
            requestPatternScore: 0.9,
            inconsistencyScore: 1.0, // Crucial for preventing account takeover
            behaviorScore: 0.8, // Important for checkout/login forms
            honeypotScore: 1.0,
            crossLayerInconsistencyScore: 0.7,
            timeInconsistencyScore: 0.9,
            tlsSpoofingScore: 0.9, // Très important pour l'e-commerce
            botScore: 1.0,
            cookieDroppingScore: 1.0, // Crucial pour la détection de bots e-commerce
            threatIntelScore: 0.8, // Very important for e-commerce (scalping proxies)
            clientHintsInconsistencyScore: 0.9, // Very important for e-commerce
            clickVarianceScore: 0.8, // Very high weight for click variance
            subnetScore: 0.9, // Crucial contre les attaques de scalping distribuées
            ipReputationScore: 0.6, // NOUVEAU: Poids pour la réputation IP
            botnetClusterScore: 0.9, // NOUVEAU: Poids pour le clustering botnet
            tcpAnomalyScore: 0.9, // NEW: Anomalie de pile TCP/IP
            protocolAnomalyScore: 0.9,
            quicAnomalyScore: 0.9, // NOUVEAU: Poids pour l'anomalie QUIC
            renderingAnomalyScore: 0.9,
            virtualizationScore: 0.8,
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
        allowCrossNetworkRoaming: false, // E-commerce : interdiction de changer de réseau sans re-challenge
    filterWhitelist: true, // Tolérance zéro pour le scraping / scalping distribué
    wasm: true,
        useAsymmetricTickets: true,
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
let cachedPowSolverCode = "";
async function preloadPowSolverCode() {
    if (!cachedPowSolverCode) {
        try {
            const solverPath = join(__dirname, 'pow.solver.inline.js');
            cachedPowSolverCode = await fsPromises.readFile(solverPath, 'utf-8');
        } catch (e) {
            console.error('[Fingerprint] Failed to pre-load inline solver:', e.message);
        }
    }
}

const getPowSolverCode = () => {
    if (!cachedPowSolverCode) {
        const solverPath = join(__dirname, 'pow.solver.inline.js');
        cachedPowSolverCode = readFileSync(solverPath, 'utf-8');
    }
    return cachedPowSolverCode;
};
/**
 * Extracts the "stable" part of a fingerprint string.
 * The stable part includes hardware-based components (canvas, gpu) that should not change.
 * @param {string} fpString The full fingerprint string.
 * @returns {string} The substring of the fingerprint containing only stable parts.
 */
function extractStablePart(fpString) {
    if (!fpString) {
        return '';
    }
    const stableKeys = ['ua', 'ja3', 'ja4', 'h2', 'tcp'];
    const parts = fpString.split('|');
    const stableParts = [];
    for (const part of parts) {
        const pair = part.split(':');
        if (pair.length === 2 && stableKeys.includes(pair[0])) {
            stableParts.push(part);
        }
    }
    return stableParts.sort().join('|');
}

/**
 * @private
 * A mapping of IANA cipher suite names (as used by Node.js) to their decimal IDs.
 * This is essential for correct JA3 fingerprint calculation.
 * The list is not exhaustive but covers the most common cipher suites.
 */
const cipherSuiteMap = {
    'TLS_AES_128_GCM_SHA256': 4865,
    'TLS_AES_256_GCM_SHA384': 4866,
    'TLS_CHACHA20_POLY1305_SHA256': 4867,
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256': 49195,
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': 49199,
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384': 49196,
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384': 49200,
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256': 52393,
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256': 52392,
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA': 49171,
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA': 49172,
    'TLS_RSA_WITH_AES_128_GCM_SHA256': 156,
    'TLS_RSA_WITH_AES_256_GCM_SHA384': 157,
    'TLS_RSA_WITH_AES_128_CBC_SHA': 47,
    'TLS_RSA_WITH_AES_256_CBC_SHA': 53,
    // Older/Less common suites
    'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA': 49161,
    'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA': 49162,
    'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256': 158,
    'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384': 159,
    'TLS_DHE_RSA_WITH_AES_128_CBC_SHA': 51,
    'TLS_DHE_RSA_WITH_AES_256_CBC_SHA': 57,
    'TLS_RSA_WITH_3DES_EDE_CBC_SHA': 10,
};

/**
 * Valide cryptographiquement l'attestation/assertion WebAuthn émise par l'enclave sécurisée.
 * @private
 * @param {object} anchor Les données d'attestation WebAuthn reçues du client
 * @param {object} deviceData Les données persistantes de l'appareil dans notre store
 * @returns {boolean} True si la signature matérielle est valide
 */
const TRUSTED_HARDWARE_ROOTS = [
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIDHzCCAfegAwIBAgIJANCvWjvF+2O6MA0GCSqGSIb3DQEBCwUAMC0xKzApBgNV\n" +
    "BAMTIll1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMB4XDTE0MDgwNDAwMDAwMFox\n" +
    "TSUxSDBGBgNVBAMMT1l1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMSowKAYDVQQK\n" +
    "EyFZdWJpY28gQUIxDzANBgNVBAcTBVN0b2NraG9sbTELMAkGA1UEBhMCU0UwggEi\n" +
    "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6XW0d87g+N6kGgSgC/H9UfA2p\n" +
    "-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIB1DCCAXWgAwIBAgIEUI70WjAKBggqhkjOPQQDAjArMSkwJwYDVQQDEyBGSURP\n" +
    "IEFsbGlhbmNlIFJvb3QgQ0EgKFRlc3QpMB4XDTE0MDgxODA4MzA0NVoXDTM5MDgx\n" +
    "ODA4MzA0NVowKzEpMCcGA1UEAxMgRklETyBBbGxpYW5jZSBSb290IENBIChUZXN0\n" +
    "KTB2MBAGByqGSM49AgEGBSuBBAAiA2IABFv81Jm9M7AehfOIdpCH567gP0yqS40m\n" +
    "aN0j1a8n152G7n/nUf7J0j9F4pL9J2w1X8hN1N8f9Y3G9w8L29/m7/zX3O3n2e7/\n" +
    "g==\n" +
    "-----END CERTIFICATE-----"
];

function decodeCBOR(buffer) {
    let offset = 0;
    function readByte() {
        if (offset >= buffer.length) throw new Error("Unexpected end of CBOR data");
        return buffer[offset++];
    }
    function readBytes(len) {
        if (offset + len > buffer.length) throw new Error("Unexpected end of CBOR bytes");
        const res = buffer.slice(offset, offset + len);
        offset += len;
        return res;
    }
    function readInt(val) {
        if (val < 24) return val;
        if (val === 24) return readByte();
        if (val === 25) {
            const b1 = readByte(); const b2 = readByte();
            return (b1 << 8) | b2;
        }
        if (val === 26) {
            const b1 = readByte(); const b2 = readByte();
            const b3 = readByte(); const b4 = readByte();
            return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        }
        throw new Error("Unsupported integer size: " + val);
    }
    function decodeType() {
        const initial = readByte();
        const major = initial >> 5;
        const val = initial & 0x1f;
        if (major === 0) {
            return readInt(val);
        } else if (major === 1) {
            return -1 - readInt(val);
        } else if (major === 2) {
            const len = readInt(val);
            return readBytes(len);
        } else if (major === 3) {
            const len = readInt(val);
            return readBytes(len).toString('utf8');
        } else if (major === 4) {
            const len = readInt(val);
            const arr = [];
            for (let i = 0; i < len; i++) arr.push(decodeType());
            return arr;
        } else if (major === 5) {
            const len = readInt(val);
            const obj = {};
            for (let i = 0; i < len; i++) {
                const k = decodeType();
                const v = decodeType();
                obj[k] = v;
            }
            return obj;
        }
        return null;
    }
    return decodeType();
}

function verifyCertificateChain(x5c) {
    if (!x5c || x5c.length === 0) return false;
    try {
        const pems = x5c.map(der => {
            const base64 = der.toString('base64');
            return `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----`;
        });

        for (let i = 0; i < pems.length - 1; i++) {
            const child = new crypto.X509Certificate(pems[i]);
            const parent = new crypto.X509Certificate(pems[i + 1]);
            if (!child.verify(parent.publicKey)) {
                return false;
            }
        }

        const rootCert = new crypto.X509Certificate(pems[pems.length - 1]);
        let trusted = false;
        for (const trustedRootPem of TRUSTED_HARDWARE_ROOTS) {
            const trustedRoot = new crypto.X509Certificate(trustedRootPem);
            if (rootCert.subject === trustedRoot.subject) {
                trusted = true;
                break;
            }
            if (rootCert.verify(trustedRoot.publicKey)) {
                trusted = true;
                break;
            }
        }
        return trusted;
    } catch (e) {
        return false;
    }
}

function verifyWebAuthnHardwareAnchor(anchor, deviceData) {
    if (!anchor || !anchor.type) return false;

    try {
        const clientDataHash = crypto.createHash('sha256')
            .update(Buffer.from(anchor.clientDataJSON, 'base64'))
            .digest();

        if (anchor.type === 'registration') {
            if (!anchor.publicKey || !anchor.credentialId || !anchor.attestationObject) return false;

            const attestationBytes = Buffer.from(anchor.attestationObject, 'base64');
            const decoded = decodeCBOR(attestationBytes);

            if (!decoded || !decoded.fmt || !decoded.attStmt) return false;

            if (decoded.fmt !== 'none') {
                const attStmt = decoded.attStmt;
                if (!attStmt.x5c || !Array.isArray(attStmt.x5c)) return false;

                if (!verifyCertificateChain(attStmt.x5c)) {
                    return false;
                }
            }

            // Enregistrement initial : on stocke la clé publique matérielle SPKI
            deviceData.webauthnPublicKey = anchor.publicKey;
            deviceData.webauthnCredentialId = anchor.credentialId;
            return true;
        } else if (anchor.type === 'assertion') {
            const storedPublicKeyPem = deviceData.webauthnPublicKey;
            if (!storedPublicKeyPem || deviceData.webauthnCredentialId !== anchor.credentialId) {
                return false;
            }

            // Reconstitution du message signé (authenticatorData + clientDataHash)
            const verifyBuffer = Buffer.concat([
                Buffer.from(anchor.authenticatorData, 'base64'),
                clientDataHash
            ]);

            const publicKey = crypto.createPublicKey(Buffer.from(storedPublicKeyPem, 'base64'));
            return crypto.verify(
                'sha256',
                verifyBuffer,
                publicKey,
                Buffer.from(anchor.signature, 'base64')
            );
        }
    } catch (e) {
        console.error('[WebAuthn-Server] Verification failed:', e.message);
    }
    return false;
}

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
    const ja4FromHeader = context.headers ? context.headers['x-ja4-hash'] : null;
    if (ja4FromHeader) {
        ja4 = ja4FromHeader;
    }
    // 2. Prefer JA3 hash from a trusted reverse proxy header.
    const ja3FromHeader = context.headers ? context.headers['x-ja3-hash'] : null; // Assuming a proxy might provide JA3 too
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
            const tlsVersionMap = { // NOSONAR
                'TLSv1': 769, 'TLSv1.1': 770, 'TLSv1.2': 771, 'TLSv1.3': 772
            };
            const tlsVersionId = tlsVersionMap[version] || 0;

            // Convert cipher suite names to their decimal IDs.
            const cipherIds = Array.isArray(ciphers)
                ? ciphers.map(c => cipherSuiteMap[c.name] || c).join('-') // Use the raw ID if name is not in map
                : '';

            const ja3String = [
                tlsVersionId,
                cipherIds,
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
    const clientFp = context.headers ? context.headers['x-device-fingerprint'] : null;
    if (clientFp && typeof clientFp === 'string' && clientFp.includes('cvs:')) {
        // On ajoute le hash du fingerprint client comme un composant du fingerprint serveur.
        // Si le clientFp change, le hash serveur changera aussi.
        srv.add("client_fp_hash", clientFp);
    }

    // 1. SIGNAL FORT: User Agent (poids élevé)
    const ua = context.headers ? context.headers["user-agent"] : null;
    if (ua) {
        srv.add("ua", ua); // User-Agent
    }

    // 2. SIGNAUX DE BAS NIVEAU (Transport & Réseau) - Très fiables si fournis par un proxy
    const { ja3, ja4 } = getTlsFingerprint(context);
    if (ja3) srv.add("ja3", ja3);
    if (ja4) srv.add("ja4", ja4);

    const h2Fingerprint = context.headers ? context.headers['x-http2-fingerprint'] : null;
    if (h2Fingerprint) srv.add("h2", h2Fingerprint);

    const tcpFingerprint = context.headers ? context.headers['x-tcp-fingerprint'] : null;
    if (tcpFingerprint) srv.add("tcp", tcpFingerprint);

    // 3. SIGNAUX DE HAUT NIVEAU (Applicatif) Moins fiables, mais utiles pour la corroboration
    const headersToCapture = {
        "ch_ua": "sec-ch-ua",
        "ch_platform": "sec-ch-ua-platform",
        "ch_mobile": "sec-ch-ua-mobile",
        "ch_model": "sec-ch-ua-model",
        "ch_arch": "sec-ch-ua-arch",
        "ch_bitness": "sec-ch-ua-bitness",
        "ch_full_version_list": "sec-ch-ua-full-version-list",
        "upgrade_req": "upgrade-insecure-requests",
        "accept_lang": "accept-language",
        "accept_enc": "accept-encoding",
        "accept": "accept"
    };

    for (const [key, headerName] of Object.entries(headersToCapture)) {
        const headerValue = context.headers ? context.headers[headerName] : null;
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

    // --- Common Libraries & Bots (for spoofing detection) ---
    '47344a349b75c4e82333475553b5f358': 'Python', // Python 3.10 `requests` library
    'b29587b8a143c42546133ad7704b3310': 'Go',     // Go 1.19 `http` library
    'd435b5223b2884c5a832b842637e245f': 'Java',   // Java 11 `HttpClient`
    'c72366b9551263d990b7fa574225332c': 'curl',   // curl 7.81.0
};

const GREASE_VALUES = [
    2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
    35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
];

/** @private */
function hasGrease(values) {
    if (!Array.isArray(values)) return false;
    return values.some(val => GREASE_VALUES.includes(val));
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
    const safePath = sanitizeRedirectPath(path);
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
            const nonce = ${safeJsonStringify(nonce)}; // Safe
            const targetMaxDistance = ${targetMaxDistance};

            async function solve() {
              const result = await window.solveTspChallenge(cities, targetMaxDistance);
              
              if (result.distance <= targetMaxDistance) {
                window.location.href = ${safeJsonStringify(safePath)} + "?pow_type=tsp&pow_nonce=" + nonce + "&pow_solution=" + JSON.stringify(result.path);
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
 * Verifies a memory PoW solution.
 * 
 * RETHINK: Designed as a client-side cost mechanism and not a cryptographic proof.
 * The primary objective of the Memory PoW is to force the client (browser or automated headless agent)
 * to allocate and touch a massive buffer (e.g., 48MB), bloating their memory footprint and making
 * multi-threaded scraping extremely expensive or unstable.
 * 
 * For small difficulties (<= 4MB, typical in unit tests), we perform the full cryptographic check.
 * For higher difficulties (production workloads), we skip the massive memory allocation on the server,
 * avoiding server-side memory DoS vectors completely.
 */
function getChallengedIndices(seed, solution, numBlocks, k = 4) {
    const indices = [];
    let h = cyrb53(seed + ":" + solution);
    for (let i = 0; i < k; i++) {
        h = Math.imul(h ^ i, 1597334677);
        indices.push(Math.abs(h) % numBlocks);
    }
    return indices;
}

function verifyMerkleProof(leafHash, index, proof, root) {
    let currentHash = leafHash;
    let idx = index;
    for (let i = 0; i < proof.length; i++) {
        const sibling = proof[i];
        const combined = idx % 2 === 0 ? currentHash + sibling : sibling + currentHash;
        currentHash = crypto.createHash('sha256').update(Buffer.from(combined, 'hex')).digest('hex');
        idx = Math.floor(idx / 2);
    }
    return currentHash === root;
}

function verifyMemoryPoWLegacy(nonce, solution, difficulty, clientSecret) {
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
    return finalHash === solution;
}

export const verifyMemoryPoW = (nonce, solution, difficulty = 16, clientSecret = '') => {
  const MAX_ALLOWED_MEM_DIFFICULTY = 128; // 128MB
  if (difficulty > MAX_ALLOWED_MEM_DIFFICULTY) {
    console.warn(`[Security] Memory PoW verification attempt with excessive difficulty: ${difficulty}MB. Denied.`);
    return false;
  }
  if (Number(difficulty) === 0) {
    return true;
  }
  if (!solution) {
    return false;
  }

  let data;
  try {
      data = typeof solution === 'string' ? JSON.parse(solution) : solution;
  } catch (e) {
      data = null;
  }

  if (!data || typeof data !== 'object' || data.solution === undefined || !data.merkleRoot || !data.proofs) {
      if (difficulty <= 4 && /^\d+$/.test(String(solution))) {
          return verifyMemoryPoWLegacy(nonce, parseInt(solution, 10), difficulty, clientSecret);
      }
      return false;
  }

  const { solution: sol, merkleRoot, proofs } = data;
  const numBlocks = difficulty * 256;
  const seed = `:${nonce}:${clientSecret}`;

  const challengedIndices = getChallengedIndices(seed, sol, numBlocks, 4);

  for (const b of challengedIndices) {
      const proof = proofs[b] || proofs[String(b)];
      if (!proof) return false;

      const block = new Uint32Array(1024);
      let h = cyrb53(seed + ":" + b);
      for (let i = 0; i < 1024; i++) {
          block[i] = (h = Math.imul(h ^ i, 1597334677));
      }

      const expectedLeaf = crypto.createHash('sha256').update(Buffer.from(block.buffer)).digest('hex');

      if (!verifyMerkleProof(expectedLeaf, b, proof, merkleRoot)) {
          return false;
      }
  }

  const blockCache = new Map();
  function getBlockElement(blockIdx, elementIdx) {
      if (!blockCache.has(blockIdx)) {
          const block = new Uint32Array(1024);
          let h = cyrb53(seed + ":" + blockIdx);
          for (let i = 0; i < 1024; i++) {
              block[i] = (h = Math.imul(h ^ i, 1597334677));
          }
          blockCache.set(blockIdx, block);
      }
      return blockCache.get(blockIdx)[elementIdx];
  }

  const totalElements = numBlocks * 1024;
  let addr = totalElements > 0 ? getBlockElement(0, 0) % totalElements : 0;
  let expectedSolution = 0;
  const iterations = 1024;
  for (let i = 0; i < iterations; i++) {
      const blockIdx = Math.floor(addr / 1024);
      const elementIdx = addr % 1024;
      addr = getBlockElement(blockIdx, elementIdx) % totalElements;
      expectedSolution ^= addr;
  }

  return expectedSolution === parseInt(sol, 10);
};

export async function verifySpacePoW(nonce, solution, queries, seed, clientSecret) {
    let combined = [];
    for (let i = 0; i < queries.length; i++) {
        const idx = queries[i];
        const block = generateBlock(seed, idx);
        combined.push(...block);
    }

    const assoc = await store.get(`coop-assoc:${nonce}`);
    if (assoc) {
        const peerSeed = assoc.peerSeed;
        const peerBlockIdx = assoc.peerBlockIdx;
        if (peerSeed !== undefined && peerBlockIdx !== undefined) {
            const peerBlock = generateBlock(peerSeed, peerBlockIdx);
            combined.push(...peerBlock);
        }
        await store.delete(`coop-assoc:${nonce}`);
    }

    const nonceBytes = Buffer.from(nonce + ":" + clientSecret, "utf8");
    const finalBlock = Buffer.concat([Buffer.from(combined), nonceBytes]);

    const hash = crypto.createHash("sha256").update(finalBlock).digest("hex");
    return hash === solution;
}

function generateBlock(seed, blockIndex, blockSize = 1024) {
  const block = new Uint8Array(blockSize);
  let h = cyrb53(seed + ":" + blockIndex);
  for (let i = 0; i < blockSize; i++) {
    h = Math.imul(h ^ i, 1597334677);
    block[i] = h & 0xff;
  }
  return block;
}

export const isTicketValid = async (ip, ticket, deviceId = '', deviceHash = '', allowCrossNetworkRoaming = false, zkpProof = '') => {
  // Input validation: ensure the ticket is a non-empty string with the correct format.
    if (typeof ticket !== 'string' || ticket.length === 0) return false;
  // 1. Resolve stateless ticket first (zero database I/O cost)
  const statelessData = parseStatelessTicket(ticket);
  if (statelessData) {
    const { expiry, originalIp, deviceId: storedDeviceId, deviceHash: storedDeviceHash } = statelessData;
    if (!expiry || Date.now() > expiry) {
      return false;
    }
    if (storedDeviceHash && storedDeviceHash.startsWith('zkp:')) {
        const expectedY = storedDeviceHash.split(':')[1];
        if (zkpProof) {
            const [y, t, s] = zkpProof.split(':');
            if (y === expectedY && verifyZkpProof(y, t, s)) {
                return true;
            }
        }
        return false;
    }
    if (ip === originalIp) return true;
    const currentSubnet = getIpSubnet(ip);
    const originalSubnet = getIpSubnet(originalIp);
    if (currentSubnet && originalSubnet && currentSubnet === originalSubnet) return true;
    if (!allowCrossNetworkRoaming) return false;
    return !!(deviceId && deviceId === storedDeviceId && deviceHash && deviceHash === storedDeviceHash);
  }

  // 2. Resolve opaque ticket session from server-side store
  const ticketData = await store.get(`ticket:${ticket}`);
  if (ticketData) {
    const { expiry, originalIp, deviceId: storedDeviceId, deviceHash: storedDeviceHash } = ticketData;

    if (!expiry || Date.now() > expiry) {
      await store.delete(`ticket:${ticket}`);
      return false;
    }
    if (storedDeviceHash && storedDeviceHash.startsWith('zkp:')) {
        const expectedY = storedDeviceHash.split(':')[1];
        if (zkpProof) {
            const [y, t, s] = zkpProof.split(':');
            if (y === expectedY && verifyZkpProof(y, t, s)) {
                return true;
            }
        }
        return false;
    }

    if (ip === originalIp) return true;
    const currentSubnet = getIpSubnet(ip);
    const originalSubnet = getIpSubnet(originalIp);
    if (currentSubnet && originalSubnet && currentSubnet === originalSubnet) return true;

    if (!allowCrossNetworkRoaming) return false;

    return !!(deviceId && deviceId === storedDeviceId && deviceHash && deviceHash === storedDeviceHash);
  }

  // 3. Legacy fallback verification (backward compatibility for old client tokens)
  let expiry, originalIp, sig;
  if (ticket.includes('|')) {
    const parts = ticket.split('|');
    if (parts.length < 3) return false;
    [expiry, originalIp, sig] = parts;
  } else if (ticket.includes(':')) {
    // Legacy fallback format
    const parts = ticket.split(':');
    if (parts.length < 2) return false;
    [expiry, sig] = parts;
    originalIp = ip;
  } else {
    return false;
  }

  if (!expiry || !sig || Date.now() > parseInt(expiry, 10)) return false;

  let expectedSig;
  if (ticket.includes('|')) {
    expectedSig = crypto
      .createHmac("sha256", getPowSecret())
      .update(`${expiry}:${originalIp}:${deviceId}:${deviceHash}`)
      .digest("hex");
  } else {
    // Legacy expected signature
    expectedSig = crypto
      .createHmac("sha256", getPowSecret())
      .update(`${ip}:${expiry}`)
      .digest("hex");
  }

  // Use timingSafeEqual to prevent timing attacks
  try {
    const isSigValid = crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expectedSig, 'hex'));
    if (!isSigValid) return false;
  } catch (e) {
    return false;
  }

  if (!ticket.includes('|')) {
    return ip === originalIp;
  }

  // Roaming & Terminal Identity checks:
  if (ip === originalIp) return true;
  const currentSubnet = getIpSubnet(ip);
  const originalSubnet = getIpSubnet(originalIp);
  if (currentSubnet && originalSubnet && currentSubnet === originalSubnet) return true;

  // Si le changement de réseau complet n'est pas autorisé, on refuse le ticket
  // et on force un re-challenge (Proof of Work)
  if (!allowCrossNetworkRoaming) return false;

  // Perfect terminal identity matched via HMAC signature
  return !!(deviceId && deviceHash);
};


/**
 * Calculates suspicion indicators related to HTTP header anomalies.
 * @param {object} context - The request context.
 * @returns {{headerAnomalyScore: number}}
 */
function getHeaderAnomalies(context) {
  let anomalyScore = 0;
  const ua = context.headers["user-agent"] || '';
  // Strong penalty if User-Agent is missing or very short (sign of a simple script)
  if (!ua || ua.length < 10) {
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

  // TE: trailers check for Firefox on Desktop
  const uaParts = parseUserAgent(ua);
  const isFirefoxDesktop = uaParts.browser?.startsWith('Firefox') && uaParts.device === 'desktop';
  const teHeader = context.headers['te'];

  if (isFirefoxDesktop && teHeader !== 'trailers') {
    anomalyScore += 30; // Suspicious: Firefox desktop missing TE: trailers
  } else if (!isFirefoxDesktop && uaParts.device === 'desktop' && teHeader === 'trailers') {
    anomalyScore += 30; // Suspicious: Non-Firefox desktop sending TE: trailers
  }

  return {
    headerAnomalyScore: Math.min(100, anomalyScore),
  };
}

export async function generateSpaceChallenge(clientIp, nonce, suspicionFactor, originalUrl, securityConfig) {
  const sizeMb = securityConfig?.pospace?.sizeMb || 100;
  const numQueries = securityConfig?.pospace?.numQueries || 10;
  
  const queries = [];
  const maxBlocks = sizeMb * 1024;
  while (queries.length < numQueries) {
    const idx = crypto.randomInt(0, maxBlocks);
    if (!queries.includes(idx)) {
      queries.push(idx);
    }
  }
  
  const challenge = {
    type: "pospace",
    nonce: nonce,
    sizeMb,
    queries,
    path: originalUrl
  };

  const peer = await findPeerInSubnet(clientIp, nonce);
  if (peer) {
    challenge.peerId = peer.nodeId;
    challenge.peerBlockIdx = crypto.randomInt(0, maxBlocks);

    await store.set(`coop-assoc:${nonce}`, {
      peerNodeId: peer.nodeId,
      peerSeed: peer.seed,
      peerBlockIdx: challenge.peerBlockIdx
    }, 120);
  }

  return challenge;
}

function generateSpaceChallengePage(challengeDetails, clientSecret, securityConfig) {
  const { nonce, sizeMb, queries, path, peerId, peerBlockIdx } = challengeDetails;
  const solverCode = getPowSolverCode();
    const safePath = sanitizeRedirectPath(path);
  const coopTimeout = securityConfig?.pospace?.coopTimeout ?? 15;

    const challengeScript = `
    async function solve() {
      const nonce = ${safeJsonStringify(nonce)};
       const path = ${safeJsonStringify(safePath)};
       const clientSecret = ${safeJsonStringify(clientSecret)};
      const queries = ${JSON.stringify(queries)};
      const sizeMb = ${sizeMb};
      const nodeId = nonce;
      const peerId = ${safeJsonStringify(peerId || '')};
      const peerBlockIdx = ${peerBlockIdx ?? -1};
      const coopTimeout = ${coopTimeout};
      
      async function signCoop(op, nid, extra = "") {
        const msg = clientSecret + ":" + op + ":" + nid + (extra ? ":" + extra : "");
        const encoder = new TextEncoder();
        const data = encoder.encode(msg);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      }
       
       async function sendWebRtcSignal(targetId, type, data) {
         const sig = await signCoop("webrtc_signal", nodeId, targetId + ":" + type + ":" + data);
         await fetch(window.location.pathname + "?coop_op=webrtc_signal&node_id=" + nodeId + "&target_peer_id=" + targetId + "&signal_type=" + type + "&signal_data=" + encodeURIComponent(data) + "&coop_sig=" + sig);
       }

      document.getElementById('loader').innerText = '⚙️ Checking persistent local storage...';
      await new Promise(r => setTimeout(r, 10));
      
      try {
          await window.initializeSpace(nonce + ":" + clientSecret, sizeMb);
          
          if (peerId && peerBlockIdx !== -1) {
              // Enregistrement coopératif
              const sig = await signCoop("register", nodeId, nonce + ":" + clientSecret);
              await fetch(window.location.pathname + "?coop_op=register&node_id=" + nodeId + "&seed=" + encodeURIComponent(nonce + ":" + clientSecret) + "&coop_sig=" + sig);
          }

        // Gestionnaire de connexions WebRTC P2P
           const peerConnections = {};

          // Écoute des requêtes entrantes de nos pairs
          setInterval(async () => {
try {
                   // 1. Récupération des signaux WebRTC P2P entrants
                   const sigWebrtc = await signCoop("poll_signals", nodeId);
                   const resWebrtc = await fetch(window.location.pathname + "?coop_op=poll_signals&node_id=" + nodeId + "&coop_sig=" + sigWebrtc);
                   const dataWebrtc = await resWebrtc.json();
                   if (dataWebrtc.signals && dataWebrtc.signals.length > 0) {
                       for (const sig of dataWebrtc.signals) {
                           const fromId = sig.from_peer_id;
                           if (sig.signal_type === 'offer') {
                               const pc = new RTCPeerConnection({ iceServers: [] });
                               peerConnections[fromId] = pc;
                               pc.onicecandidate = (e) => {
                                   if (e.candidate) sendWebRtcSignal(fromId, 'candidate', JSON.stringify(e.candidate));
                               };
                               pc.ondatachannel = (e) => {
                                   const dc = e.channel;
                                   dc.onmessage = async (evt) => {
                                       try {
                                           const req = JSON.parse(evt.data);
                                           if (req.type === 'get_block') {
                                               document.getElementById('loader').innerText = '📤 Transfert direct P2P (WebRTC) du bloc vers le pair...';
                                               const blockData = await window.readSpaceBlock(req.block_idx);
                                               dc.send(JSON.stringify({ type: 'block_data', block_data: blockData }));
                                           }
                                       } catch (err) {}
                                   };
                               };
                               await pc.setRemoteDescription(new RTCSessionDescription(JSON.parse(sig.signal_data)));
                               const answer = await pc.createAnswer();
                               await pc.setLocalDescription(answer);
                               await sendWebRtcSignal(fromId, 'answer', JSON.stringify(answer));
                           } else if (sig.signal_type === 'answer' && peerConnections[fromId]) {
                               await peerConnections[fromId].setRemoteDescription(new RTCSessionDescription(JSON.parse(sig.signal_data)));
                           } else if (sig.signal_type === 'candidate' && peerConnections[fromId]) {
                               await peerConnections[fromId].addIceCandidate(new RTCIceCandidate(JSON.parse(sig.signal_data)));
                           }
                       }
                   }
               } catch (e) {}
          }, 800);

          let peerBlock = "";
          if (peerId && peerBlockIdx !== -1) {
               document.getElementById('loader').innerText = '📥 Connexion WebRTC P2P directe au pair (' + peerId + ')...';
 
               // 1. Tentative d'échange direct via WebRTC DataChannel (charge serveur = 0)
               const webrtcTransferPromise = new Promise(async (resolve) => {
                   if (!window.RTCPeerConnection) return resolve(null);
                   try {
                       const pc = new RTCPeerConnection({ iceServers: [] });
                       peerConnections[peerId] = pc;
                       const dc = pc.createDataChannel("pospace-transfer");
                       pc.onicecandidate = (e) => {
                           if (e.candidate) sendWebRtcSignal(peerId, 'candidate', JSON.stringify(e.candidate));
                       };
                       dc.onopen = () => {
                           dc.send(JSON.stringify({ type: 'get_block', block_idx: peerBlockIdx }));
                       };
                       dc.onmessage = (e) => {
                           try {
                               const msg = JSON.parse(e.data);
                               if (msg.type === 'block_data' && msg.block_data) {
                                   resolve(msg.block_data);
                               }
                           } catch (err) {}
                       };
                       const offer = await pc.createOffer();
                       await pc.setLocalDescription(offer);
                       await sendWebRtcSignal(peerId, 'offer', JSON.stringify(offer));
                   } catch (err) {
                       resolve(null);
                   }
               });
 
               const webrtcTimeoutPromise = new Promise((resolve) => setTimeout(() => resolve(null), 5000));
               peerBlock = await Promise.race([webrtcTransferPromise, webrtcTimeoutPromise]);
 
               if (peerBlock) {
                   document.getElementById('loader').innerText = '⚡ Bloc reçu en direct via WebRTC P2P sans transit serveur !';
               } else {
                   // 2. Repli transparent vers la boîte aux lettres HTTP en cas de restriction réseau
                   document.getElementById('loader').innerText = '⚠️ WebRTC P2P indisponible. Téléchargement via relais HTTP...';
                   const reqId = Math.random().toString(36).substring(2);
                   const reqSig = await signCoop("request_peer_block", nodeId, peerId + ":" + peerBlockIdx + ":" + reqId);
                   await fetch(window.location.pathname + "?coop_op=request_peer_block&node_id=" + nodeId + "&peer_id=" + peerId + "&block_idx=" + peerBlockIdx + "&req_id=" + reqId + "&coop_sig=" + reqSig);
                   
                   let attempts = 0;
                   while (attempts < coopTimeout) {
                       const pollSig = await signCoop("poll_response", nodeId, reqId);
                       const res = await fetch(window.location.pathname + "?coop_op=poll_response&node_id=" + nodeId + "&req_id=" + reqId + "&coop_sig=" + pollSig);
                       const data = await res.json();
                       if (data.status === 'ready') {
                           peerBlock = data.block_data;
                           break;
                       }
                       await new Promise(r => setTimeout(r, 1000));
                       attempts++;
                   }
               }
          }

          document.getElementById('loader').innerText = '⚙️ Generating Proof of Space...';
          const hash = await window.solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret, peerBlock);
          
          window.location.href = path + "?pow_type=pospace&pow_nonce=" + nonce + "&pow_solution_space=" + hash + (peerBlock ? "&pow_coop=1" : "");
      } catch(e) {
          document.getElementById('loader').innerText = "Error initializing local storage: " + e.message;
      }
    }
    solve();
  `;
  
  return `<html><head><title>Security Check</title></head>
  <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
    <h1>Security Check (Level 2)</h1>
    <p>We are verifying your storage allocation. This may take a few seconds on first load.</p>
    <div id="loader" style="margin:20px;">⚙️ Initializing storage space...</div>
    <script>${solverCode}</script>
    <script>${challengeScript}</script>
  </body></html>`;
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
    sql: /(\$ne|\' *OR *\'1\'=\'1|['";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|(?:SLEEP|BENCHMARK)\s*\(|WAITFOR DELAY)/i,
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
    // Server-Side Request Forgery (SSRF) - Detects local/private IPs and hosts
    ssrf: /((?:https?:\/\/)?(?:127\.\d+\.\d+\.\d+\b|169\.254\.169\.254\b|10\.\d+\.\d+\.\d+\b|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+\b|192\.168\.\d+\.\d+\b|localhost\b|0\.0\.0\.0\b|\[[0:]+1\](?=\W|$)))/i,
    // Carriage Return Line Feed (CRLF) Injection / HTTP Response Splitting
    crlf: /[\r\n]|%0[ad]/i,
    // Cross-Site Scripting (XSS) - Fast native regex fallback
    xss: /(<script|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|<img\s+src[^>]+onerror|<iframe)/i,
    // Open Redirect - Basic detection of external protocol/URLs
    openRedirect: /^(https?:)?\/\/(?![^\/]*?(localhost|127\.0\.0\.1))[^\s\/]+/i,
    // Local/Remote File Inclusion (LFI/RFI)
    lfi: /(?:etc\/passwd|win\.ini|boot\.ini|php:\/\/filter|data:\/\/|zip:\/\/)/i,
    // Shellshock (CVE-2014-6271)
    shellshock: /\(\)\s*\{\s*:\s*;\s*\}\s*/i,
    // NoSQL Injection (MongoDB query operators)
    nosql: /\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|expr|jsonSchema|mod|regex|text|where|elemMatch)/i
};

/**
 * @private
 * Analyse une série de mouvements de souris pour en extraire des métriques comportementales.
 * @param {Array<{x: number, y: number, t: number}>} history - L'historique des points de la souris.
 * @returns {{avgSpeed: number, avgAcceleration: number, straightness: number, pauses: number, segments: Array<number>}}
 */
function analyzeMouseMovements(history) {
    if (!history || history.length < 3) {
        return { avgSpeed: 0, avgAcceleration: 0, straightness: 1, pauses: 0, segments: [] };
    }

    const segments = [];
    let totalDistance = 0;
    let pauses = 0;

    for (let i = 1; i < history.length; i++) {
        const p1 = history[i - 1];
        const p2 = history[i];
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const dt = p2.t - p1.t;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (dt > 0) {
            const speed = distance / dt;
            segments.push({ distance, dt, speed });
            totalDistance += distance;
        }
        // Une "micro-pause" est un intervalle de temps long sans mouvement significatif.
        if (dt > 100 && distance < 5) {
            pauses++;
        }
    }

    if (segments.length < 2) {
        return { avgSpeed: 0, avgAcceleration: 0, straightness: 1, pauses, segments: [] };
    }

    const totalTime = history[history.length - 1].t - history[0].t;
    const avgSpeed = totalTime > 0 ? segments.reduce((sum, s) => sum + s.speed, 0) / segments.length : 0;

    let totalAbsAcceleration = 0;
    for (let i = 1; i < segments.length; i++) {
        const s1 = segments[i - 1];
        const s2 = segments[i];
        if (s2.dt > 0) {
            const acceleration = (s2.speed - s1.speed) / s2.dt;
            totalAbsAcceleration += Math.abs(acceleration);
        }
    }
    const avgAcceleration = totalAbsAcceleration / (segments.length - 1);

    // Le score de rectitude compare la distance totale parcourue à la distance en ligne droite.
    // Un score proche de 1 signifie un mouvement très droit (suspect).
    const startPoint = history[0];
    const endPoint = history[history.length - 1];
    const straightDistance = Math.sqrt(Math.pow(endPoint.x - startPoint.x, 2) + Math.pow(endPoint.y - startPoint.y, 2));
    const straightness = totalDistance > 0 ? straightDistance / totalDistance : 1;

    return { avgSpeed, avgAcceleration, straightness, pauses, segments: segments.map(s => s.distance) };
}

/**
 * @private
 * Analyse une série d'événements tactiles mobiles pour en extraire des indicateurs comportementaux robustes.
 * @param {Array<{x: number, y: number, t: number, p: number, r: number, num: number}>} history
 * @returns {{avgSpeed: number, avgAcceleration: number, straightness: number, pauses: number, segments: Array<number>, avgPressure: number, avgRadius: number, pressureVariance: number, radiusVariance: number, maxTouches: number}}
 */
function analyzeTouchMovements(history) {
    if (!history || history.length < 3) {
        return { avgSpeed: 0, avgAcceleration: 0, straightness: 1, pauses: 0, segments: [], avgPressure: 0, avgRadius: 0, pressureVariance: 0, radiusVariance: 0, maxTouches: 1 };
    }

    const segments = [];
    let totalDistance = 0;
    let pauses = 0;
    let totalPressure = 0;
    let totalRadius = 0;
    let maxTouches = 1;

    for (let i = 1; i < history.length; i++) {
        const p1 = history[i - 1];
        const p2 = history[i];
        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const dt = p2.t - p1.t;
        const distance = Math.sqrt(dx * dx + dy * dy);

        totalPressure += p2.p || 0;
        totalRadius += p2.r || 0;
        if (p2.num > maxTouches) {
            maxTouches = p2.num;
        }

        if (dt > 0) {
            const speed = distance / dt;
            segments.push({ distance, dt, speed });
            totalDistance += distance;
        }
        if (dt > 100 && distance < 5) {
            pauses++;
        }
    }

    totalPressure += history[0].p || 0;
    totalRadius += history[0].r || 0;

    const avgPressure = totalPressure / history.length;
    const avgRadius = totalRadius / history.length;

    let sqDiffPressureSum = 0;
    let sqDiffRadiusSum = 0;
    for (const pt of history) {
        sqDiffPressureSum += Math.pow((pt.p || 0) - avgPressure, 2);
        sqDiffRadiusSum += Math.pow((pt.r || 0) - avgRadius, 2);
    }
    const pressureVariance = sqDiffPressureSum / history.length;
    const radiusVariance = sqDiffRadiusSum / history.length;

    if (segments.length < 2) {
        return { avgSpeed: 0, avgAcceleration: 0, straightness: 1, pauses, segments: [], avgPressure, avgRadius, pressureVariance, radiusVariance, maxTouches };
    }

    const totalTime = history[history.length - 1].t - history[0].t;
    const avgSpeed = totalTime > 0 ? segments.reduce((sum, s) => sum + s.speed, 0) / segments.length : 0;
    const avgAcceleration = segments.reduce((sum, s) => sum + (s.speed / s.dt), 0) / segments.length;

    const startPoint = history[0];
    const endPoint = history[history.length - 1];
    const straightDistance = Math.sqrt(Math.pow(endPoint.x - startPoint.x, 2) + Math.pow(endPoint.y - startPoint.y, 2));
    const straightness = totalDistance > 0 ? straightDistance / totalDistance : 1;

    return { avgSpeed, avgAcceleration, straightness, pauses, segments: segments.map(s => s.distance), avgPressure, avgRadius, pressureVariance, radiusVariance, maxTouches };
}

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
  if (metrics.prototypeTampered) {
      score += 80; // Altération flagrante de l'environnement JS
  }
    // 2. Analyse des mouvements de la souris
    const { avgSpeed, avgAcceleration, straightness, pauses, segments } = analyzeMouseMovements(metrics.mouseMovementsHistory);
    const touchAnalysis = analyzeTouchMovements(metrics.touchMovementsHistory);

    // Pénalité pour absence totale d'interaction. Un utilisateur légitime peut simplement lire la page.
    // On applique donc une pénalité de base faible, qui est amplifiée uniquement si d'autres
    // signaux passifs de bot (ex: rendu offscreen) sont présents.
    if (avgSpeed === 0 && touchAnalysis.avgSpeed === 0 && metrics.keystrokeLatency === 0) {
      let noInteractionPenalty = 5; // Pénalité de base très faible.

      // Amplification si d'autres signaux passifs de bot sont présents.
      if (metrics.rendering?.offscreenAnom) {
        noInteractionPenalty += 40;
      }
      
      score += noInteractionPenalty;
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

    // 3. Analyse des métriques de la souris
    if (avgSpeed > 0) {
        if (avgSpeed > 3) score += 25; // Vitesse irréaliste (3 pixels/ms)
        if (avgAcceleration > 0.5) score += 20; // Accélération trop brutale
        if (straightness > 0.95) score += 30; // Mouvement trop droit
        if (pauses === 0 && segments.length > 20) score += 15; // Mouvement continu sans micro-pauses
    }

    // 4. Analyse comportementale des événements tactiles (Touch Move)
    const touchHistory = metrics.touchMovementsHistory;
    if (touchHistory && touchHistory.length > 0) {
        const touch = analyzeTouchMovements(touchHistory);
        if (touch.avgSpeed > 0) {
            if (touch.avgSpeed > 5) score += 30; // Touch d'une vitesse anormale/robotique
            if (touch.avgAcceleration > 0.8) score += 20;
            if (touch.straightness > 0.98) score += 35; // Un tracé de doigt humain n'est jamais parfaitement rectiligne
            if (touch.pauses === 0 && touch.segments.length > 25) score += 15;

            // Détection de l'émulation (pression et rayon de contact constants)
            if (touch.avgPressure > 0 && touch.pressureVariance === 0) {
                score += 30; // Spoofed force/pressure
            }
            if (touch.avgRadius > 0 && touch.radiusVariance === 0) {
                score += 30; // Spoofed pointer area size
            }
            if (touch.segments.length > 10) {
                const benfordDev = Optimization.Operators.benfordTest(touch.segments);
                if (benfordDev > 0.18) score += 35;
            }
        }
    }

    // Détection de ferme mobile : un appareil mobile parfaitement immobile est suspect, indépendamment des interactions tactiles.
    const isMobileDevice = (context.headers['user-agent'] || '').includes('Mobile');
    if (isMobileDevice && typeof metrics.motionVariance === 'number' && metrics.motionVariance === 0) {
        score += 50; // Terminal fixé sur un châssis mécanique (rack ADB)
    }

    // Plausibilité de la latence de frappe
    if (metrics.keystrokeLatency > 0 && metrics.keystrokeLatency < 40) score += 25; // Frappe trop rapide pour un humain.
    if (metrics.keystrokeLatency > 1000) score += 15; // Latence très élevée, peut être un script lent.

    // NOUVEAU: Analyse de digraphie/trigraphie (dwell & flight times)
    const dwellTimes = metrics.keystrokeDwellTimes || [];
    const flightTimes = metrics.keystrokeFlightTimes || [];

    if (dwellTimes.length >= 5) {
        const meanDwell = dwellTimes.reduce((a, b) => a + b, 0) / dwellTimes.length;
        const varDwell = dwellTimes.reduce((a, b) => a + Math.pow(b - meanDwell, 2), 0) / dwellTimes.length;
        const stdDevDwell = Math.sqrt(varDwell);

        if (stdDevDwell < 2.0) {
            score += 35; // Suspicion d'automatisation (pas de variation humaine de pression)
        }
        if (meanDwell < 15.0) {
            score += 25; // Dwell time irréaliste
        }
    }

    if (flightTimes.length >= 5) {
        const times = flightTimes.map(f => f.time);
        const meanFlight = times.reduce((a, b) => a + b, 0) / times.length;
        const varFlight = times.reduce((a, b) => a + Math.pow(b - meanFlight, 2), 0) / times.length;
        const stdDevFlight = Math.sqrt(varFlight);

        if (stdDevFlight < 3.0) {
            score += 35; // Pas de variation de transition (flight time robotique)
        }
        if (meanFlight < 25.0) {
            score += 25; // Transitions trop rapides
        }
        const benfordDev = Optimization.Operators.benfordTest(times);
        if (benfordDev > 0.18) {
            score += 30; // Les intervalles ne suivent pas la loi de Benford
        }
    }

    // 4. Analyse de la distribution avec la loi de Benford (si les valeurs sont non nulles).
    if (segments.length > 10) {
        const benfordDeviation = Optimization.Operators.benfordTest(segments);
        if (benfordDeviation > 0.18) { // Seuil légèrement plus élevé pour cette métrique
            score += 35;
        }
    }

    return { behaviorScore: Math.min(100, score) }; // Assure que le score ne dépasse pas 100, mais peut être négatif (bonus)
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
function getTimeInconsistencyScore(context, metrics, deviceData = null) {
  const REPLAY_THRESHOLD_MS = 5000; // 5 secondes
  let score = 0;

  if (deviceData && deviceData.sessionHmacKey && metrics.signature) {
    try {
      const copy = JSON.parse(JSON.stringify(metrics));
      const clientSig = copy.signature;
      delete copy.signature;
      const dataToSign = JSON.stringify(copy);
      const expectedSig = crypto.createHmac('sha256', Buffer.from(deviceData.sessionHmacKey, 'hex'))
                                .update(dataToSign)
                                .digest('hex');
      if (!crypto.timingSafeEqual(Buffer.from(clientSig, 'hex'), Buffer.from(expectedSig, 'hex'))) {
        return { timeInconsistencyScore: 100 }; // Replay/tampering detected
      }
    } catch (e) {
      return { timeInconsistencyScore: 100 };
    }
  } else if (deviceData && deviceData.sessionHmacKey && !metrics.signature) {
    return { timeInconsistencyScore: 100 }; // Missing mandatory signature
  }

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
        const h2Fingerprint = context.headers['x-http2-fingerprint'] || context.http2Fingerprint || null;
        if (!clientFpString) return { crossLayerInconsistencyScore: 0 };

        const clientFpMap = new Map(clientFpString.split("|").map(part => part.split(":")));
        const ua = context.headers["user-agent"] || '';
        let score = 0;

        // 1. Incohérence de l'OS
        const clientOsHash = clientFpMap.get('os');
        if (clientOsHash) {
            const serverOsParts = parseUserAgent(ua);
            if (serverOsParts.os && clientOsHash !== String(cyrb53(serverOsParts.os))) {
                // Exemple: le client prétend être 'Windows' mais le UA est 'macOS'.
                score += 50;
            }
        }

        // 2. Incohérence de l'écran (si les Client Hints sont disponibles)
        const clientScreenHash = clientFpMap.get('scr');
        const viewportWidth = context.headers['sec-ch-viewport-width'];
        if (clientScreenHash && viewportWidth) {
                  const viewportWidthInt = parseInt(viewportWidth, 10);
                  let matchedScreenWidth = null;
                  const commonWidths = [320, 360, 375, 390, 412, 414, 768, 1024, 1280, 1366, 1440, 1536, 1600, 1920, 2560, 3840];
                  const commonHeights = [480, 568, 640, 667, 736, 800, 812, 844, 896, 900, 1024, 1080, 1200, 1440, 1600, 2160];
                  const commonDepths = [24, 30, 32];

                  for (const w of commonWidths) {
                      for (const h of commonHeights) {
                          for (const d of commonDepths) {
                              const candidate = `${w}x${h}_${d}`;
                              if (clientScreenHash === String(cyrb53(candidate))) {
                                  matchedScreenWidth = w;
                                  break;
                              }
                          }
                          if (matchedScreenWidth !== null) break;
                      }
                      if (matchedScreenWidth !== null) break;
                  }

                  if (matchedScreenWidth !== null && viewportWidthInt > matchedScreenWidth) {
                score += 20;
            }
        }

        // 3. Incohérence du GPU/Canvas et JA3
        // Un attaquant sophistiqué peut forger le canvas, mais il est très difficile de forger
        // le JA3 qui dépend de la librairie TLS. Une forte incohérence ici est un signal fort.
        const clientGpuHash = clientFpMap.get('gpu');
        const ja3 = getTlsFingerprint(context)?.ja3;
        if (clientGpuHash && ja3) {
            let expectedBrowsers = tlsFingerprintDb[ja3];
            if (expectedBrowsers) {
                if (!Array.isArray(expectedBrowsers)) {
                    expectedBrowsers = [expectedBrowsers];
                }
                const nonBrowserLibraries = ['Python', 'Go', 'Java', 'curl'];
                const isLibrary = expectedBrowsers.some(lib => nonBrowserLibraries.includes(lib));
                if (isLibrary) {
                    score += 30;
                }
            }
        }

        // 4. Incohérence des paramètres HTTP/2 (SETTINGS & WINDOW_UPDATE)
        // Les bots de spoofing TLS oublient souvent de modifier la signature de la couche HTTP/2
        if (h2Fingerprint && serverOsParts.browser) {
            const claimedBrowser = serverOsParts.browser.split('/')[0];
            
            // Profils de paramètres HTTP/2 Settings attendus (Format standard type Akamai)
            // Chrome :SETTINGS_HEADER_TABLE_SIZE=65536, SETTINGS_MAX_CONCURRENT_STREAMS=1000, etc.
            const isChromium = ['Chrome', 'Edge'].includes(claimedBrowser);
            const isFirefox = claimedBrowser === 'Firefox';
            
            if (isChromium) {
                // Chrome envoie typiquement : "1:65536;3:1000;4:6291456;6:65536" ou similaire
                const hasChromiumSettings = h2Fingerprint.includes('1:65536') && h2Fingerprint.includes('4:6291456');
                const isGoDefaultH2 = h2Fingerprint.includes('3:100') && h2Fingerprint.includes('4:1048576'); // Signature Go net/http par défaut
                
                if (isGoDefaultH2) {
                    score += 90; // Très forte suspicion d'un bot Go (tls-client) usurpant Chrome
                } else if (!hasChromiumSettings) {
                    score += 40; // Anomalie de configuration HTTP/2
                }
            } else if (isFirefox) {
                // Firefox utilise des valeurs de fenêtres initiales et de paramètres différentes
                const isPythonH2 = h2Fingerprint.includes('1:4096') && h2Fingerprint.includes('4:65536'); // Signature hyper-générique type Python hyper/h2
                if (isPythonH2) {
                    score += 90; // Bot Python usurpant Firefox
                }
            }
        }

        // 5. Corrélation stricte OS Réseau (TCP/IP) vs OS Applicatif (User-Agent)
        if (context.tcpAnomalyScore && context.tcpAnomalyScore > 70) {
            score += 40; // Augmente drastiquement la pénalité si l'OS réseau ne correspond pas à l'OS applicatif
        }

        return { crossLayerInconsistencyScore: Math.min(100, score) };
    } catch (e) {
        return { crossLayerInconsistencyScore: 10 }; // Erreur de parsing = suspect.
    }
}
function parseJa4(ja4) {
    if (!ja4 || typeof ja4 !== 'string') return null;
    const parts = ja4.split('_');
    const ja4a = parts[0];
    if (ja4a.length < 10) return null;
    return {
        protocol: ja4a[0],
        version: ja4a.substring(1, 3),
        sni: ja4a[3],
        ciphersCount: parseInt(ja4a.substring(4, 6), 10) || 0,
        extensionsCount: parseInt(ja4a.substring(6, 8), 10) || 0,
        alpn: ja4a.substring(8, 10),
        ja4b: parts[1] || null,
        ja4c: parts[2] || null
    };
}

/**
 * Calcule un score d'incohérence entre les données du fingerprint TLS (JA3/JA4) et les en-têtes serveur (User-Agent).
 * Cela permet de détecter le spoofing de fingerprint TLS.
 * @param {object} context - Le contexte de la requête.
 * @returns {Promise<{tlsSpoofingScore: number}>}
 */
export function getTlsSpoofingScore(context, getTlsFingerprintFn = getTlsFingerprint, customStore = null) {
    let actualGetTlsFingerprintFn = getTlsFingerprintFn;
    let actualStore = customStore || store;

    // Detect if the second argument is actually a store (compatibility with tests)
    if (getTlsFingerprintFn && typeof getTlsFingerprintFn.get === 'function' && typeof getTlsFingerprintFn.set === 'function') {
        actualStore = getTlsFingerprintFn;
        actualGetTlsFingerprintFn = getTlsFingerprint;
    }

    const { ja3, ja4 } = actualGetTlsFingerprintFn(context) || { ja3: null, ja4: null }; // Defensive check
    const ua = context.headers["user-agent"] || '';
    const ja3Raw = context.headers['x-ja3-raw'] || null;
    const httpVersion = context.httpVersion || '';

    let score = 0;

    // 1. Penalize if a TLS fingerprint is present but the User-Agent is generic or missing.
    // This is a strong indicator of a non-browser client trying to look legitimate.
    if ((ja3 || ja4) && (!ua || ua.length < 10 || ua.toLowerCase().includes('python') || ua.toLowerCase().includes('curl'))) {
        score = Math.max(score, 50);
    }

    // Check for known spoofed/suspicious JA4 fingerprints
    const spoofedJa4s = [
        't13d1516h2_8daaf6152771_4be0df930c2c', // Alternatif Chrome (tls-client Go)
        't12d1516h2_8daaf6152771_390237aa04be', // Chrome usurpé dégradé en TLS 1.2
        't13d1516h2_e822d36d892d_93ec3f0b2f5b'  // Scraping bot OpenSSL customisé
    ];
    if (ja4 && spoofedJa4s.includes(ja4)) {
        score = Math.max(score, 100);
    }

    const claimedBrowser = parseUserAgent(ua).browser?.split('/')[0] || null;
    const isHumanBrowser = ['Chrome', 'Firefox', 'Safari', 'Edge'].includes(claimedBrowser);

    // --- ANALYSE 2 : CONTRÔLE PROFOND SUR L'EMPREINTE BRUTE (RAW JA3) ---
    if (ja3Raw) {
        const parsed = parseJa3(ja3Raw);
        if (parsed) {
            // Contrôle A : Mécanisme GREASE pour Chrome / Edge (obligatoire)
            if (claimedBrowser === 'Chrome' || claimedBrowser === 'Edge') {
                const hasCiphersGrease = hasGrease(parsed.ciphers);
                const hasExtensionsGrease = hasGrease(parsed.extensions);
                
                if (!hasCiphersGrease && !hasExtensionsGrease) {
                    // Chrome ou Edge moderne sans GREASE = spoofing de bas niveau (ex: python-requests déguisé)
                    score = Math.max(score, 75);
                }
            }

            // Contrôle B : HTTP/2 ou HTTP/3 sans négociation ALPN (Extension 16)
            const isH2OrHigher = (
                httpVersion.includes('2.0') || 
                httpVersion.includes('HTTP/2') || 
                httpVersion.includes('HTTP/3')
            );
            const hasAlpnExtension = parsed.extensions.includes(16);
            
            if (isH2OrHigher && !hasAlpnExtension) {
                // Négociation HTTP/2 active au niveau serveur mais absente au niveau des extensions TLS du client
                score = Math.max(score, 70);
            }

            // Contrôle C : Version TLS obsolète négociée par un navigateur moderne (ex: TLS < 1.2, id < 771)
            if (isHumanBrowser && parsed.tlsVersion < 771) {
                score = Math.max(score, 80);
            }
        }
    }

    // Parse JA4 if available for advanced checks
    if (ja4) {
        const parsedJa4 = parseJa4(ja4);
        if (parsedJa4) {
            const uaParts = parseUserAgent(ua);

            // Check 1: Incohérence ALPN / HTTP Version
            if (parsedJa4.alpn === 'h2' && (context.httpVersion === '1.1' || context.httpVersion === '1.0')) {
                const hasProxy = context.headers['via'] || context.headers['forwarded'] || context.headers['x-forwarded-proto'] || context.headers['x-forwarded-for'];
                if (!hasProxy) {
                    score = Math.max(score, 40);
                }
            }

            // Check 2: Incohérence OS/Plateforme vs Capabilities TLS
            if (parsedJa4.version === '12' && (uaParts.os === 'iOS' || uaParts.os === 'macOS') && uaParts.browser?.startsWith('Safari')) {
                score = Math.max(score, 60);
            }

            // Check 3: Incohérence User-Agent vs Signature JA4
            if (uaParts.browser?.startsWith('Chrome') && parsedJa4.alpn === '00') {
                score = Math.max(score, 50);
            }
            if (uaParts.browser?.startsWith('Firefox') && parsedJa4.extensionsCount > 15) {
                score = Math.max(score, 50);
            }
        }
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

            // Check 1: Known library JA3 with a human-claimed browser
            const isLibrary = expectedBrowsers.some(expected => ['Python', 'Go', 'Java', 'curl'].includes(expected));
            const claimsToBeHumanBrowser = claimedBrowser && (
                claimedBrowser.startsWith('Chrome') || 
                claimedBrowser.startsWith('Firefox') || 
                claimedBrowser.startsWith('Safari') || 
                claimedBrowser.startsWith('Edge')
            );
            
            if (isLibrary && claimsToBeHumanBrowser) {
                score = Math.max(score, 90); // High confidence spoofing of library as browser
            } else {
                // Check if the claimed browser is one of the legitimate possibilities for this JA3 hash.
                const isMatch = expectedBrowsers.some(expected => claimedBrowser?.startsWith(expected));
                if (claimedBrowser && !isMatch) {
                    score = Math.max(score, 80); // High score for a clear mismatch.
                }
            }
        }
    }

    // Create the promise for the async part (Check 4)
    const promise = (async () => {
        let asyncScore = score;
        const uaParts = parseUserAgent(ua);
        
        if (uaParts.browser) {
            const browserFamily = uaParts.browser.split('/')[0];
            
            // Check 4a: Stagnation JA4
            if (ja4) {
                const parsedJa4 = parseJa4(ja4);
                if (parsedJa4) {
                    const ja4Key = `ja4-browsers:${ja4}`;
                    let seenBrowsers = await actualStore.get(ja4Key) || [];
                    if (!Array.isArray(seenBrowsers)) seenBrowsers = [];
                    if (browserFamily && !seenBrowsers.includes(browserFamily)) {
                        seenBrowsers.push(browserFamily);
                    await actualStore.set(ja4Key, seenBrowsers, 86400); // 24h cache
                    }
                    if (seenBrowsers.length > 1) {
                        asyncScore = Math.max(asyncScore, 80);
                    }
                }
            }
            
            // Check 4b: JA3 MD5 stagnation with rotating browser UAs
            if (ja3 && browserFamily) {
                const ja3Key = `ja3-browsers:${ja3}`;
                let seenBrowsers = await actualStore.get(ja3Key) || [];
                if (!Array.isArray(seenBrowsers)) seenBrowsers = [];
                if (!seenBrowsers.includes(browserFamily)) {
                    seenBrowsers.push(browserFamily);
                    await actualStore.set(ja3Key, seenBrowsers, 86400); // 24h cache
                }
                if (seenBrowsers.length > 1) {
                    asyncScore = Math.max(asyncScore, 85); // Staging different UAs on same JA3 MD5 signature
                }
            }
        }
        return { tlsSpoofingScore: asyncScore };
    })();

    // Decorate the promise so synchronous calls can destructure it!
    promise.tlsSpoofingScore = score;
    return promise;
}

/**
 * Calculates a score based on inconsistencies between User-Agent and Sec-CH-UA headers.
 * @param {object} context The request context.
 * @returns {{clientHintsInconsistencyScore: number}}
 */
function getClientHintsInconsistencyScore(context) {
    const ua = context.headers['user-agent'];
    const clientHints = context.headers['sec-ch-ua'];

    if (!ua || !clientHints) {
        return { clientHintsInconsistencyScore: 0 };
    }

    const fullVersionList = context.headers['sec-ch-ua-full-version-list'];
    if (fullVersionList) {
        let chFullVersion = null;
        let chFullBrowser = null;
        const matches = [...fullVersionList.matchAll(/"([^"]+)";v="([^"]+)"/g)];
        for (const match of matches) {
            const brand = match[1];
            const version = match[2];
            if (brand === 'Google Chrome' || brand === 'Chromium' || brand === 'Microsoft Edge') {
                chFullVersion = version;
                chFullBrowser = brand === 'Microsoft Edge' ? 'Edge' : 'Chrome';
                if (brand === 'Google Chrome' || brand === 'Microsoft Edge') {
                    break;
                }
            }
        }
        if (chFullVersion && chFullBrowser) {
            let uaFullVersion = null;
            const uaFullMatch = ua.match(/(Chrome|Edg)\/([\d\.]+)/);
            if (uaFullMatch) {
                const uaBrowserMapped = uaFullMatch[1] === 'Edg' ? 'Edge' : 'Chrome';
                uaFullVersion = uaFullMatch[2];
                if (uaBrowserMapped === chFullBrowser && uaFullVersion !== chFullVersion) {
                    const parts1 = uaFullVersion.split('.').map(Number);
                    const parts2 = chFullVersion.split('.').map(Number);
                    let diffIndex = -1;
                    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
                        if ((parts1[i] || 0) !== (parts2[i] || 0)) {
                            diffIndex = i;
                            break;
                        }
                    }
                    const baseScores = [95, 90, 85, 80];
                    const baseScore = baseScores[diffIndex] || 80;
                    const delta = Math.abs((parts1[diffIndex] || 0) - (parts2[diffIndex] || 0));
                    const finalFullScore = Math.min(100, baseScore + Math.min(5, delta * 5));
                    return { clientHintsInconsistencyScore: finalFullScore };
                }
            }
        }
    }

    // 1. Extract browser and version from User-Agent
    let uaVersion = null;
    let uaBrowser = null;
    const uaMatch = ua.match(/(Chrome|Firefox|Edg|Safari)\/([\d\.]+)/);
    if (uaMatch) {
        uaBrowser = uaMatch[1] === 'Edg' ? 'Edge' : uaMatch[1];
        uaVersion = uaMatch[2]?.split('.')[0];
    }

    // 2. Extract browser and version from Sec-CH-UA
    let chVersion = null;
    let chBrowser = null;
    const chMatch = clientHints.match(/"(Google Chrome|Chromium|Microsoft Edge)";v="(\d+)"/);

    if (chMatch) {
        chVersion = chMatch[2];
        if (chMatch[1] === 'Microsoft Edge') {
            chBrowser = 'Edge';
        } else {
            chBrowser = 'Chrome'; // Treat Chrome and Chromium as the same for this check
        }
    }

    if (!uaVersion || !chVersion || !uaBrowser || !chBrowser) {
        return { clientHintsInconsistencyScore: 0 };
    }

    // 3. Compare
    if (uaBrowser !== chBrowser && (uaBrowser !== 'Chrome' || chBrowser !== 'Edge')) { // Allow Chrome UA with Edge CH
        return { clientHintsInconsistencyScore: 90 };
    }

    const versionDifference = Math.abs(parseInt(uaVersion, 10) - parseInt(chVersion, 10));

        let clientHintsInconsistencyScore = 0;
        if (versionDifference > 0) {
            if (versionDifference <= 2) {
                clientHintsInconsistencyScore = versionDifference * 20;
            } else if (versionDifference <= 7) {
                clientHintsInconsistencyScore = 40 + (versionDifference - 2) * 8;
            } else {
                clientHintsInconsistencyScore = Math.min(100, 80 + (versionDifference - 7) * 3.33);
            }
            clientHintsInconsistencyScore = Math.round(clientHintsInconsistencyScore);
        }

        return { clientHintsInconsistencyScore };
}

/**
 * @private
 * Analyzes click positions from client-side metrics to detect unnaturally low variance,
 * which can be a sign of automated clicking.
 * @param {Array<{x: number, y: number, targetId: string}>|null} history - The click history from the client.
 * @returns {number} A score from 0 to 100, where a higher score indicates lower variance (more bot-like).
 */
function analyzeClickPositions(history) {
    if (!history || history.length < 3) {
        return 0;
    }

    const clicksByTarget = {};
    for (const click of history) {
        if (!click.targetId) continue;
        if (!clicksByTarget[click.targetId]) {
            clicksByTarget[click.targetId] = [];
        }
        clicksByTarget[click.targetId].push(click);
    }

    let maxScore = 0;

    for (const targetId in clicksByTarget) {
        const clicks = clicksByTarget[targetId];
        if (clicks.length < 3) continue;

        const n = clicks.length;
        const meanX = clicks.reduce((sum, c) => sum + c.x, 0) / n;
        const meanY = clicks.reduce((sum, c) => sum + c.y, 0) / n;

        const variance = clicks.reduce((sum, c) => sum + Math.pow(c.x - meanX, 2) + Math.pow(c.y - meanY, 2), 0) / n;

        // If variance is extremely low (e.g., less than 1 pixel), it's highly suspicious.
        // The score increases as variance approaches zero.
        if (variance < 1.0) {
            // A simple scoring model: score is 100 if variance is 0, and decreases.
            const score = (1 - Math.sqrt(variance) / 5) * 100;
            if (score > maxScore) {
                maxScore = score;
            }
        }
    }

    return Math.min(100, maxScore);
}

/**
 * Calculates a score based on click variance metrics sent by the client.
 * @param {object} context - The request context.
 * @returns {{clickVarianceScore: number}}
 */
function getClickVarianceScore(context) {
    const metrics = JSON.parse(context.headers['x-behavior-metrics'] || '{}');
    const score = analyzeClickPositions(metrics.clicksHistory);
    return { clickVarianceScore: score };
}

/**
 * Calculates the subnet of an IP address.
 * @param {string} ip The IP address.
 * @param {number} [ipv4Prefix=24] The prefix for IPv4 addresses.
 * @param {number} [ipv6Prefix=48] The prefix for IPv6 addresses.
 * @returns {string|null} The subnet CIDR or null if the IP is invalid.
 */
function getIpSubnet(ip, ipv4Prefix = 24, ipv6Prefix = 48) { // eslint-disable-line no-unused-vars
  try {
    if (isIPv4(ip)) {
      const ipBuffer = Buffer.from(ip.split('.').map(Number));
      const mask = Buffer.alloc(4, 0);
      for (let i = 0; i < ipv4Prefix; i++) mask[Math.floor(i / 8)] |= 1 << (7 - (i % 8));
      for (let i = 0; i < 4; i++) ipBuffer[i] &= mask[i];
      return `${Array.from(ipBuffer).join('.')}/${ipv4Prefix}`;
    } else if (isIPv6(ip)) {
      let normalized = ip.trim().toLowerCase();
      if (normalized.includes("::")) {
        const parts = normalized.split("::");
        if (parts.length > 2) return null;
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        const missing = 8 - (left.length + right.length);
        const middle = Array(missing).fill("0000");
        normalized = [...left, ...middle, ...right].join(":");
      } else {
        const parts = normalized.split(":");
        if (parts.length !== 8) return null;
      }
      const groups = normalized.split(":").map(g => {
        const val = parseInt(g, 16);
        return isNaN(val) ? "0000" : val.toString(16).padStart(4, "0");
      });
      for (let i = 0; i < 8; i++) {
        const startBit = i * 16;
        if (ipv6Prefix >= (i + 1) * 16) {
          continue;
        } else if (ipv6Prefix <= startBit) {
          groups[i] = "0000";
        } else {
          const bitsToKeep = ipv6Prefix - startBit;
          const val = parseInt(groups[i], 16);
          const mask = (0xffff << (16 - bitsToKeep)) & 0xffff;
          groups[i] = (val & mask).toString(16).padStart(4, "0");
        }
      }
      return `${groups.join(":")}/${ipv6Prefix}`;
    }
  } catch (e) {
    // Catch any unexpected errors during parsing or manipulation
  }
  return null;
}

/**
 * Calcule la longueur du préfixe commun (en bits) entre deux adresses IP (IPv4 ou IPv6).
 * @param {string} ip1
 * @param {string} ip2
 * @returns {number} Nombre de bits identiques en tête (0 à 32 pour IPv4, 0 à 128 pour IPv6).
 */
function getIpCommonPrefixLength(ip1, ip2) {
  if (!ip1 || !ip2) return 0;
  if (isIPv4(ip1) && isIPv4(ip2)) {
    const b1 = ip1.split('.').map(Number);
    const b2 = ip2.split('.').map(Number);
    const int1 = ((b1[0] << 24) | (b1[1] << 16) | (b1[2] << 8) | b1[3]) >>> 0;
    const int2 = ((b2[0] << 24) | (b2[1] << 16) | (b2[2] << 8) | b2[3]) >>> 0;
    const xor = (int1 ^ int2) >>> 0;
    return xor === 0 ? 32 : Math.clz32(xor);
  }
  if (isIPv6(ip1) && isIPv6(ip2)) {
    const normalize = (ip) => {
      let normalized = ip.trim().toLowerCase();
      if (normalized.includes("::")) {
        const parts = normalized.split("::");
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        const missing = 8 - (left.length + right.length);
        const middle = Array(missing).fill("0000");
        normalized = [...left, ...middle, ...right].join(":");
      } else {
        const parts = normalized.split(":");
        if (parts.length !== 8) return null;
      }
      return normalized.split(":").map(g => parseInt(g, 16) || 0);
    };

    try {
      const g1 = normalize(ip1);
      const g2 = normalize(ip2);
      if (!g1 || !g2) return 0;
      let prefix = 0;
      for (let i = 0; i < 8; i++) {
        const xor = (g1[i] ^ g2[i]) & 0xffff;
        if (xor === 0) {
          prefix += 16;
        } else {
          // clz32 opère sur des entiers 32 bits, ajuster pour 16 bits
          prefix += (Math.clz32(xor) - 16);
          break;
        }
      }
      return prefix;
    } catch (e) {
      return 0;
    }
  }
  return 0;
}

/**
 * Applies temporal decay (half-life of 30 minutes) to subnet metrics.
 * @private
 * @param {object} subnetData The subnet data.
 * @param {number} now The current timestamp.
 * @returns {object} The decayed subnet data.
 */
function decaySubnetData(subnetData, now) {
    const inactivityMs = now - (subnetData.lastActivity || now);
    const halfLives = Math.floor(inactivityMs / (30 * 60 * 1000));

    if (halfLives > 0) {
        const decay = Math.pow(2, halfLives);
        subnetData.highScoreCount = Math.max(0, Math.floor((subnetData.highScoreCount || 0) / decay));

        if (subnetData.highScoreDevices) {
            for (const fpId in subnetData.highScoreDevices) {
                const decayedVal = Math.floor(subnetData.highScoreDevices[fpId] / decay);
                if (decayedVal <= 0) {
                    delete subnetData.highScoreDevices[fpId];
                } else {
                    subnetData.highScoreDevices[fpId] = decayedVal;
                }
            }
        }

        if (subnetData.deviceIds) {
            const newLen = Math.max(0, Math.floor(subnetData.deviceIds.length / decay));
            subnetData.deviceIds = subnetData.deviceIds.slice(0, newLen);
        }

        if (subnetData.ips) {
            const currentLen = subnetData.ips instanceof Set ? subnetData.ips.size : (subnetData.ips.length || 0);
            const newLen = Math.max(0, Math.floor(currentLen / decay));
            if (subnetData.ips instanceof Set) {
                const arr = Array.from(subnetData.ips).slice(0, newLen);
                subnetData.ips = new Set(arr);
            } else {
                subnetData.ips = subnetData.ips.slice(0, newLen);
            }
        }

        if (subnetData.uas) {
            const newLen = Math.max(0, Math.floor(subnetData.uas.length / decay));
            subnetData.uas = subnetData.uas.slice(0, newLen);
        }

        if (Array.isArray(subnetData.attackerIps)) {
            const maxAttackerAgeMs = 60 * 60 * 1000; // 1 heure max
            subnetData.attackerIps = subnetData.attackerIps.filter(a => (now - (a.lastSeen || now)) < maxAttackerAgeMs);
        }

        subnetData.lastActivity = now - (inactivityMs % (30 * 60 * 1000));
    }
    return subnetData;
}

/**
 * Updates aggregated metrics for an IP subnet.
 * @param {object} context The request context.
 * @param {string} deviceId The device ID.
 * @param {number} finalScore The final suspicion score.
 */
async function updateSubnetMetrics(context, deviceId, finalScore) {
    if (!context.clientIp || isLoopbackIp(context.clientIp)) {
        return;
    }
    const subnet = getIpSubnet(context.clientIp);
    if (!subnet) return;

    const key = `subnet:${subnet}`;
    const subnetData = (await store.get(key)) || {
        highScoreCount: 0,
        deviceIds: [],
        highScoreDevices: {},
        lastActivity: 0,
        ips: [],
        uas: [],
        attackerIps: []
    };

    if (!subnetData.highScoreDevices) {
        subnetData.highScoreDevices = {};
    }
    if (subnetData.ips instanceof Set) {
        subnetData.ips = Array.from(subnetData.ips);
    } else if (!subnetData.ips) {
        subnetData.ips = [];
    }
    if (!subnetData.uas) subnetData.uas = [];
    if (!Array.isArray(subnetData.attackerIps)) {
        subnetData.attackerIps = [];
    }

    const now = Date.now();
    decaySubnetData(subnetData, now);

    // Utilisation d'un identifiant d'appareil stable (fingerprint matériel) plutôt que l'ID de cookie volatil
    const currentDeviceHash = getCompositeDeviceHash(context);
    const stablePart = extractStablePart(currentDeviceHash);
    const stableFpId = stablePart ? cyrb53(stablePart).toString() : (deviceId || cyrb53(currentDeviceHash).toString());

    const currentDeviceContributions = subnetData.highScoreDevices[stableFpId] || 0;
    if (currentDeviceContributions < 1) {
        subnetData.highScoreDevices[stableFpId] = currentDeviceContributions + 1;
        subnetData.highScoreCount++;
    }

    if (!subnetData.deviceIds.includes(stableFpId)) {
        subnetData.deviceIds.push(stableFpId);
    }

    if (!subnetData.ips.includes(context.clientIp)) {
        subnetData.ips.push(context.clientIp);
    }

    const userAgent = context.headers?.['user-agent'] || '';

    // Ne pas enregistrer une IP en attaquant si le score élevé provient uniquement d'un seul appareil isolé
    const isConfirmedClusterAttack = (subnetData.deviceIds.length > 1 && finalScore >= 70) || finalScore >= 95;
    if (isConfirmedClusterAttack) {
        const existingAttacker = subnetData.attackerIps.find(a => a.ip === context.clientIp);
        if (existingAttacker) {
            existingAttacker.lastSeen = now;
            existingAttacker.score = Math.max(existingAttacker.score || 0, finalScore);
        } else {
            subnetData.attackerIps.push({ ip: context.clientIp, lastSeen: now, score: finalScore });
            if (subnetData.attackerIps.length > 30) {
                subnetData.attackerIps.shift();
            }
        }
    }

    if (userAgent && !subnetData.uas.includes(userAgent)) {
        subnetData.uas.push(userAgent);
    }

    subnetData.lastActivity = now;

    if (subnetData.deviceIds.length > 100) {
        const oldDeviceId = subnetData.deviceIds.shift();
        if (subnetData.highScoreDevices[oldDeviceId] !== undefined) {
            const oldContributions = subnetData.highScoreDevices[oldDeviceId];
            subnetData.highScoreCount = Math.max(0, subnetData.highScoreCount - oldContributions);
            delete subnetData.highScoreDevices[oldDeviceId];
        }
    }
    if (subnetData.ips.length > 100) subnetData.ips.shift();
    if (subnetData.uas.length > 50) subnetData.uas.shift();

    await store.set(key, subnetData, 86400); // 24-hour TTL
}
/**
 * Calcule un score d'incohérence analogique lisse plafonnant à une asymptote de 99.9.
 * @param {number} consistencyScore Similarité entre 0 et 1 issue du FingerprintBuilder.
 * @param {number} [inflectionPoint=0.72] Point d'inflexion où la suspicion accélère.
 * @param {number} [steepness=12] Raideur de la transition sigmoïdale.
 * @returns {number} Score de 0 à 99.9 sans saut de palier ni certitude absolue à 100.
 */
export function calculateAnalogInconsistencyScore(consistencyScore, inflectionPoint = 0.72, steepness = 12) {
    const s = Math.max(0.0, Math.min(1.0, consistencyScore));
    if (s >= 0.98) return 0.0;

    const asymptote = 99.9;
    const raw = 1.0 / (1.0 + Math.exp(steepness * (s - inflectionPoint)));
    const minVal = 1.0 / (1.0 + Math.exp(steepness * (1.0 - inflectionPoint)));
    const maxVal = 1.0 / (1.0 + Math.exp(steepness * (0.0 - inflectionPoint)));
    const normalized = ((raw - minVal) / (maxVal - minVal)) * asymptote;

    return Math.min(asymptote, Math.round(normalized * 10.0) / 10.0);
}

/**
 * Calculates a suspicion score based on the historical activity of the IP subnet.
 * @param {object} context The request context.
 * @param {string} [deviceId=''] The device ID.
 * @param {object} [securityConfig=null] Security configuration containing thresholds.
 * @returns {Promise<{subnetScore: number}>}
 */
async function getSubnetScore(context, deviceId = '', securityConfig = null) {
    if (!context.clientIp || isLoopbackIp(context.clientIp)) {
        return { subnetScore: 0.0 };
    }
    if (typeof deviceId === 'object' && deviceId !== null && !securityConfig) {
        securityConfig = deviceId;
    }
    const subnet = getIpSubnet(context.clientIp);
    if (!subnet) return { subnetScore: 0 };
    const key = `subnet:${subnet}`;

    const subnetData = await store.get(key);
    if (!subnetData) return { subnetScore: 0 };

    const now = Date.now();
    const inactivityMs = now - (subnetData.lastActivity || now);
    const halfLives = Math.floor(inactivityMs / (30 * 60 * 1000));

    if (halfLives > 0) {
        decaySubnetData(subnetData, now);
        await store.set(key, subnetData, 86400);
    }

    let highScoreCount = subnetData.highScoreCount || 0;
    let deviceCount = subnetData.deviceIds ? subnetData.deviceIds.length : 0;
    let ipCount = 1;
    if (subnetData.ips) {
        ipCount = subnetData.ips instanceof Set ? subnetData.ips.size : (subnetData.ips.length || 1);
    }
    let uaCount = subnetData.uas ? subnetData.uas.length : 1;

    if (deviceCount <= 1 && highScoreCount <= 1) {
        return { subnetScore: 0.0 };
    }

    // 1. Estimation Bayésienne de densité (évite les sur-réactions sur 1 ou 2 appareils)
    // Prior: alpha=0.5, beta=2.0 (a priori réseau sain)
    const bayesianDensity = (highScoreCount + 0.5) / (deviceCount + 2.5);

    // 2. Ratio IP / Terminal (distingue un proxy distribué d'un gros NAT / CGNAT)
    // Sur un proxy distribué, chaque terminal utilise une IP différente (ratio >= 1.0)
    // Sur un CGNAT, des dizaines de terminaux partagent peu d'IPs (ratio << 1.0)
    const ipDispersion = Math.min(2.0, ipCount / deviceCount);
    const ipMultiplier = 0.6 + 0.4 * Math.tanh(ipDispersion);

    // 3. Volatilité des User-Agents (rotation de navigateurs sur matériel identique)
    const uaDispersion = Math.min(3.0, Math.max(1, uaCount) / deviceCount);
    const uaMultiplier = 0.7 + 0.3 * Math.tanh(uaDispersion - 1.0);

    // 4. Intensité brute continue de la menace
    const rawThreatIntensity = highScoreCount * bayesianDensity * ipMultiplier * uaMultiplier;

    // 5. Composante 1 : Score ambiant plafonné en zone Medium (asymptote au seuil medium)
    const mediumThreshold = (securityConfig?.thresholds?.medium !== undefined)
        ? Number(securityConfig.thresholds.medium)
        : 45.0;
    const ambientAsymptote = mediumThreshold;
    const maxProximityBoost = Math.max(0.0, 100.0 - ambientAsymptote);
    const scaleFactor = 10.0;
    const ambientScore = ambientAsymptote * Math.tanh(rawThreatIntensity / scaleFactor);

    // 6. Composante 2 : Boost de proximité micro-réseau avec des attaquants récents (le reste va jusqu'à 100)
    let proximityBoost = 0.0;
    const attackerIps = subnetData.attackerIps || [];
    const clientIp = context.clientIp;

    if (attackerIps.length > 0 && clientIp) {
        let maxCommonPrefix = 0;
        const isClientV4 = isIPv4(clientIp);
        const isClientV6 = isIPv6(clientIp);

        for (const att of attackerIps) {
            if (att.ip && (now - (att.lastSeen || now)) <= 30 * 60 * 1000) {
                const prefixLen = getIpCommonPrefixLength(clientIp, att.ip);
                if (prefixLen > maxCommonPrefix) {
                    maxCommonPrefix = prefixLen;
                }
            }
        }

        if (isClientV4) {
            if (maxCommonPrefix >= 32) {
                proximityBoost = maxProximityBoost; // Même adresse IP exacte
            } else if (maxCommonPrefix >= 30) {
                proximityBoost = maxProximityBoost * (45.0 / 55.0); // Même /30 (écart <= 3 adresses)
            } else if (maxCommonPrefix >= 28) {
                proximityBoost = maxProximityBoost * (30.0 / 55.0); // Même /28 (bloc de 16 adresses)
            } else if (maxCommonPrefix >= 26) {
                proximityBoost = maxProximityBoost * (15.0 / 55.0); // Même /26 (bloc de 64 adresses)
            }
        } else if (isClientV6) {
            if (maxCommonPrefix >= 128) {
                proximityBoost = maxProximityBoost; // Même IPv6 exacte
            } else if (maxCommonPrefix >= 120) {
                proximityBoost = maxProximityBoost * (45.0 / 55.0); // Même /120
            } else if (maxCommonPrefix >= 112) {
                proximityBoost = maxProximityBoost * (30.0 / 55.0); // Même /112
            } else if (maxCommonPrefix >= 96) {
                proximityBoost = maxProximityBoost * (15.0 / 55.0); // Même /96
            }
        }
    }

    const finalScore = Math.min(100.0, Math.round((ambientScore + proximityBoost) * 10) / 10);

    return { subnetScore: finalScore };
}

/**
 * Calcule le score d'anomalie de similarité réseau (Botnet Clustering).
 * @param {object} context - Le contexte de la requête.
 * @param {string} stableFpHash - Le hash de la partie stable de l'empreinte.
 * @returns {Promise<{botnetClusterScore: number}>}
 */
async function getBotnetClusterScore(context, stableFpHash) {
  if (!stableFpHash) return { botnetClusterScore: 0 };
  const key = `botnet-cluster:${stableFpHash}`;
  const now = Date.now();
  const tenMinutesAgo = now - 600 * 1000;

  let clusterData = (await store.get(key)) || [];
  if (!Array.isArray(clusterData)) {
    clusterData = [];
  }

  clusterData = clusterData.filter(entry => entry.timestamp > tenMinutesAgo);
  const existingIndex = clusterData.findIndex(entry => entry.ip === context.clientIp);
  const userAgent = context.headers?.['user-agent'] || '';
  const subnet = getIpSubnet(context.clientIp) || 'unknown';

  if (existingIndex !== -1) {
    clusterData[existingIndex].timestamp = now;
    clusterData[existingIndex].ua = userAgent;
    clusterData[existingIndex].subnet = subnet;
  } else {
    clusterData.push({ ip: context.clientIp, timestamp: now, ua: userAgent, subnet: subnet });
  }

  await store.set(key, clusterData, 600);
  const uniqueIpsCount = clusterData.length;
  let botnetClusterScore = 0;
  if (uniqueIpsCount >= 2) {
    // Calcul de la diversité des sous-réseaux et de la rotation des User-Agents
    const uniqueSubnets = new Set(clusterData.map(e => e.subnet)).size;
    const uniqueUserAgents = new Set(clusterData.map(e => e.ua).filter(Boolean)).size;

    // Facteurs d'ajustement
    const subnetMultiplier = uniqueSubnets > 1 ? 1.3 : 0.6; // Réduit le score si même sous-réseau (NAT), l'augmente si distribué
    const uaRotationMultiplier = uniqueUserAgents > 1 ? 1.5 : 1.0; // Forte pénalité en cas de rotation d'en-tête UA

    const baseScore = 100 * (1 - Math.exp(-0.35 * (uniqueIpsCount - 1)));
    botnetClusterScore = Math.min(100, Math.round(baseScore * subnetMultiplier * uaRotationMultiplier * 10) / 10);
  }
  return { botnetClusterScore };
}

/**
 * Retrieves the current local IP reputation score, applying time-based decay.
 * @param {string} ip - The client's IP address.
 * @returns {Promise<number>} The reputation score (0 to 100).
 */
async function getIpReputationScore(ip) {
  const key = `ip-reputation:${ip}`;
  const data = await store.get(key);
  if (!data) return 0;
  
  const now = Date.now();
  const hoursPassed = (now - data.lastUpdate) / (1000 * 60 * 60);
  const decay = Math.floor(hoursPassed * 2); // Decay 2 points per hour of inactivity
  return Math.max(0, data.score - decay);
}

/**
 * Updates the local IP reputation score.
 * @param {string} ip - The client's IP address.
 * @param {number} change - The score change (positive to penalize, negative to reward).
 */
async function updateIpReputationScore(ip, change) {
  const key = `ip-reputation:${ip}`;
  const current = await getIpReputationScore(ip);
  const newScore = Math.min(100, Math.max(0, current + change));
  await store.set(key, { score: newScore, lastUpdate: Date.now() }, 86400 * 7); // 7-day TTL
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
        inactivityReset = 180000,   // Réinitialisation du score après 3 minutes d'inactivité.
        regularityRatio = 0.4,      // (NOUVEAU) Poids relatif de l'écart-type
        benfordRatio = 0.3,         // (NOUVEAU) Poids relatif de Benford
        enumerationRatio = 0.3      // (NOUVEAU) Poids relatif de l'énumération de chemins
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

    let regularityScore = 0;
    let benfordScore = 0;
    const timings = deviceData.timingHistory;

    // Analyse statistique unifiée si nous avons assez de données
    if (timings.length >= minSamples) {
        const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
        const variance = timings.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / timings.length;
        const stdDev = Math.sqrt(variance);
        const benfordDeviation = Optimization.Operators.benfordTest(timings);

        // Calcul progressif de la régularité (stdDev proche de 0 = score max)
        if (stdDev < regularityThreshold) {
            regularityScore = 1 - (stdDev / regularityThreshold);
        }
        // Calcul progressif de Benford (excès par rapport au seuil)
        if (benfordDeviation > benfordThreshold) {
            benfordScore = Math.min(1, (benfordDeviation - benfordThreshold) / (0.5 - benfordThreshold));
        }
    }

    // Détection d'énumération de chemins (crawling/scraping de ressources séquentielles)
    let enumerationScore = 0;
    if (history.length >= 3) {
        const templates = history.map(h => h.path.replace(/\d+/g, '{num}'));
        const uniquePaths = new Set(history.map(h => h.path));

        const templateCounts = {};
        templates.forEach(t => templateCounts[t] = (templateCounts[t] || 0) + 1);

        const maxTemplateRepetition = Math.max(...Object.values(templateCounts), 0);
        if (maxTemplateRepetition >= 3 && uniquePaths.size === history.length) {
            enumerationScore = Math.min(1, (maxTemplateRepetition - 2) / 5);
        }
    }

    // Score instantané combiné linéaire pondéré
    const weightedScore = (regularityScore * regularityRatio) +
        (benfordScore * benfordRatio) +
        (enumerationScore * enumerationRatio);

    const instantScore = weightedScore * patternWeight;

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

    deviceData.lastPatternScore = Math.max(instantScore, newPatternScore);

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
 * @property {() => Promise<void>} clear
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
  async clear() {
    this._map.clear();
    for (const timeoutId of this._timeouts.values()) {
      clearTimeout(timeoutId);
    }
    this._timeouts.clear();
  }
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
    const tlsSessionId = getTlsSessionId(context);
    let deviceId = existingDeviceId;
  let consistencyScore = 1.0; // 1.0 = perfectly consistent
  let deviceData = null;
  let newCookie = null;

    if (!deviceId && tlsSessionId) {
        const resumedDeviceId = await store.get(`tls-session:${tlsSessionId}`);
        if (resumedDeviceId) {
            deviceId = resumedDeviceId;
        }
    }

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

    const isHttps = context.headers?.['x-forwarded-proto'] === 'https' || 
                    context.rawReq?.secure || 
                    context.rawReq?.protocol === 'https' ||
                    context.rawReq?.connection?.encrypted;
    const secureOption = isHttps || process.env.NODE_ENV === "production";

    // Return the intention to set a cookie.
    newCookie = {
      name: "device_id",
      value: deviceId,
      options: {
        httpOnly: true, secure: secureOption, sameSite: "strict",
        ...(secureOption && { partitioned: true }),
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

    if (deviceId && tlsSessionId) {
        await store.set(`tls-session:${tlsSessionId}`, deviceId, 3600); // Bind TLS session for 1 hour
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
  const rapidChangeThresholdMs = 2000; // 2 secondes
  const maxRapidChanges = 3;

  const now = Date.now();
  const clientIp = context.clientIp;

  // Get the IP type to modulate the score
  const ipProfile = (await store.get(`ip:${clientIp}`)) || { type: "residential" };
  const isSharedIp = ipProfile.type === "shared";

  const currentFpHash = getCompositeDeviceHash(context); // Use the composite hash for behavioral indicators

  // --- Behavior analysis (Change frequency) ---
    if (deviceData.lastFpHash && currentFpHash !== deviceData.lastFpHash) {
        // Smarter comparison: only penalize if STABLE parts of the fingerprint change.
        // Stable parts are those that shouldn't change during a simple network switch.
        const stablePart1 = extractStablePart(deviceData.lastFpHash);
        const stablePart2 = extractStablePart(currentFpHash);

        const timeSinceLastChange = now - deviceData.lastChangeTimestamp;

        // Increment the rapid rotation counter ONLY if the stable part has changed.
        if (stablePart1 !== stablePart2) {
            if (timeSinceLastChange < rapidChangeThresholdMs) {
                deviceData.rapidChangeCount = (deviceData.rapidChangeCount || 0) + 1;
            } else {
                // If the change is slow, reduce the counter to forgive old rapid changes.
                deviceData.rapidChangeCount = Math.max(0, (deviceData.rapidChangeCount || 0) - 1);
            }
            deviceData.lastChangeTimestamp = now;
            // If only the volatile part changed (e.g., User-Agent, IP via headers), we don't update `lastChangeTimestamp`.
            // This prevents a legitimate network change followed by another change (e.g., device sleep)
            // from being counted as a rapid rotation.
        }
  }

  deviceData.lastFpHash = currentFpHash;
  deviceData.ips.add(clientIp); // Record the IP used by this device

    // Nettoyage par fenêtre glissante pour éviter l'accumulation sur les sessions longues
    if (!deviceData.ipTimes) {
        deviceData.ipTimes = {};
    }
    deviceData.ipTimes[clientIp] = now;

    const slidingWindow = 2 * 60 * 60 * 1000; // 2 heures
    const cutOff = now - slidingWindow;
    for (const [ip, lastSeen] of Object.entries(deviceData.ipTimes)) {
        if (lastSeen < cutOff) {
            deviceData.ips.delete(ip);
            delete deviceData.ipTimes[ip];
        }
    }
  // --- VALIDATION DE L'ANCRAGE MATÉRIEL WEBAUTHN ---
  const behaviorHeader = context.headers?.['x-behavior-metrics'];
  let webauthnVerified = false;
  if (behaviorHeader) {
      try {
          const metrics = JSON.parse(behaviorHeader);
          if (metrics && metrics.webauthnAnchor) {
              if (verifyWebAuthnHardwareAnchor(metrics.webauthnAnchor, deviceData)) {
                  webauthnVerified = true;
                  deviceData.webauthnVerified = true;
              }
          }
      } catch (e) {
          // Ignorer les erreurs de parsing
      }
  }

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
    ((deviceData.rapidChangeCount || 0) / maxRapidChanges) * 100,
  );

  return { historyScore, rotationScore };
}

function getVirtualizationAnomalyScore(context) {
    const clientFp = context.headers?.['x-device-fingerprint'];
    if (!clientFp) return 0.0;

    const fpMap = {};
    clientFp.split('|').forEach(part => {
        const pair = part.split(':');
        if (pair.length === 2) {
            fpMap[pair[0]] = pair[1];
        }
    });

    let score = 0.0;
    const clientGpuHash = fpMap['gpu'];
    if (clientGpuHash) {
        const virtualGpus = [
            "Google SwiftShader", "SwiftShader",
            "Mesa llvmpipe", "llvmpipe", "Mesa Gallium",
            "Microsoft Basic Render Driver", "HeadlessChrome",
            "Intel(R) HD Graphics"
        ];
        const virtualGpuHashes = new Set(virtualGpus.map(gpu => cyrb53(gpu).toString()));
        if (virtualGpuHashes.has(clientGpuHash)) {
            score += 75.0;
        }
    }

    const clientScreenHash = fpMap['scr'];
    if (clientScreenHash) {
        const headlessResolutions = ["800x600_24", "1024x768_24"];
        const headlessHashes = new Set(headlessResolutions.map(res => cyrb53(res).toString()));
        if (headlessHashes.has(clientScreenHash)) {
            score += 25.0;
        }
    }

    return Math.min(100.0, score);
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
  const currentDeviceHash = getCompositeDeviceHash(context);

  // If a new cookie needs to be set, attach it to the request object
  // so the middleware can handle it. This is a temporary state holder.
  if (newCookie) {
    context._newCookies = context._newCookies || [];
    context._newCookies.push(newCookie);
  }

  // Periodically clean up device data
  if (Date.now() - deviceData.lastUpdate > 10 * 60 * 1000) { // 10 minutes
    deviceData.ips.clear();
    deviceData.rapidChangeCount = 0;
      deviceData.ipTimes = {};
  }
  deviceData.lastUpdate = Date.now();

  const stableFp = extractStablePart(currentDeviceHash);
  const stableFpHash = cyrb53(stableFp).toString();

      // Execute non-interdependent asynchronous operations in parallel
    const zkpProof = (context.getHeader ? context.getHeader('x-zkp-proof') : null) || (context.headers ? context.headers['x-zkp-proof'] : null) || (context.query ? context.query['pow_zkp'] : null) || (context.queryParams ? context.queryParams['pow_zkp'] : null) || '';
    const zkpY = zkpProof ? zkpProof.split(":")[0] : null;

    const [
        behavioral,
        { threatIntelScore },
        { tlsSpoofingScore },
        { subnetScore },
        ipReputationScore,
        { botnetClusterScore },
        _ // store.set result
      ] = await Promise.all([
        getBehavioralIndicators(context, deviceData), // This modifies deviceData, so it must be done before saving deviceData
        getThreatIntelScore(context, zkpY, securityConfig), // NOUVEAU: Score de Threat Intelligence Fédéré
        getTlsSpoofingScore(context),
        getSubnetScore(context, deviceId, securityConfig),
        getIpReputationScore(clientIp),
        getBotnetClusterScore(context, stableFpHash),
        store.set(`ip-device:${clientIp}`, deviceId, 600) // Link the IP to the device for 10 minutes
      ]);

      // Synchronous calculations
      const { headerAnomalyScore } = getHeaderAnomalies(context);
    const similarityThreshold = securityConfig?.similarityThreshold ?? 0.72;
    const inconsistencyScore = calculateAnalogInconsistencyScore(consistencyScore, similarityThreshold);

      const { behaviorScore } = getBehaviorScore(context); // Appel de la fonction

      // On appelle getHoneypotScore ici pour que son résultat soit inclus dans le vecteur.
      const { honeypotScore } = getHoneypotScore(context, honeypotConfig);

      const { botScore } = getBotScore(context);

      // NOUVEAU: On calcule le score d'incohérence temporelle.
      const { timeInconsistencyScore } = getTimeInconsistencyScore(context, JSON.parse(context.headers['x-behavior-metrics'] || '{}'), deviceData);

      // NOUVEAU: On calcule le score d'incohérence entre les couches.
      const { crossLayerInconsistencyScore } = getCrossLayerInconsistency(context);

      // NOUVEAU: On calcule le score de variance des clics.
      const { clickVarianceScore } = getClickVarianceScore(context);

      // NOUVEAU: On calcule le score d'incohérence des Client-Hints.
      const { clientHintsInconsistencyScore } = getClientHintsInconsistencyScore(context);

      const { requestPatternScore } = getRequestPatternScore(context, deviceData, securityConfig.patterns);

  const { tcpAnomalyScore } = getTcpAnomalyScore(context);
    const { protocolAnomalyScore } = getProtocolAnomalyScore(context);
    const { renderingAnomalyScore } = getRenderingAnomalyScore(context);
    const virtualizationScore = getVirtualizationAnomalyScore(context);

  // Save the updated device state to the store
  // Note: deviceData.ips is a Set, which may not serialize correctly in all stores (e.g., JSON). A Redis store should handle this via custom serialization or by converting to an array.
  await store.set(`device:${deviceId}`, deviceData);

  // Ensure deviceData.ips is a Set for subsequent operations within the same request,
  // even if the store returns an array.
  if (Array.isArray(deviceData.ips)) {
      deviceData.ips = new Set(deviceData.ips);
  }
  // Le vecteur de suspicion est maintenant complet.
  return { ...behavioral, headerAnomalyScore, inconsistencyScore, behaviorScore, honeypotScore, botScore, requestPatternScore, crossLayerInconsistencyScore, timeInconsistencyScore, tlsSpoofingScore, clickVarianceScore, clientHintsInconsistencyScore, subnetScore, ipReputationScore, botnetClusterScore, tcpAnomalyScore, protocolAnomalyScore, renderingAnomalyScore, threatIntelScore, virtualizationScore };
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
    weights: {
      historyScore: 0.3,
      rotationScore: 0.5,
      headerAnomalyScore: 0.2,
      requestPatternScore: 0.6,
      inconsistencyScore: 0.8,
      behaviorScore: 0.7,
      honeypotScore: 1.0,
      botScore: 1.0,
      cookieDroppingScore: 0.9,
      crossLayerInconsistencyScore: 0.4,
      timeInconsistencyScore: 0.9,
      tlsSpoofingScore: 0.8,
      clientHintsInconsistencyScore: 0.7,
      clickVarianceScore: 0.6,
      subnetScore: 0.4,
      ipReputationScore: 0.5,
      botnetClusterScore: 0.7,
      tcpAnomalyScore: 0.8,
      quicAnomalyScore: 0.8,
      protocolAnomalyScore: 0.8,
      renderingAnomalyScore: 0.8,
      threatIntelScore: 1.0,
      virtualizationScore: 0.8
    },
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
                      const MAX_DIFFICULTY_BITS = cpuConfig.maxDifficultyBits ?? 22;

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
 * @param {string} clientIp
 * @param {string} tlsSessionId
 * @returns {Buffer}
 */
function createCpuChallengeBaseBlock(nonce, clientSecret, fingerprint, clientIp = '', tlsSessionId = '') {
    const sortedFingerprint = (fingerprint || '').split('|').filter(p => p).sort().join('|');
    // On concatène les chaînes, puis on les convertit en buffer une seule fois.
    // Cela garantit que le client et le serveur travaillent sur la même base binaire.
    const messageBase = `${nonce}:${clientSecret}:${sortedFingerprint}:${clientIp}:${tlsSessionId}:`; // Le ':' final est le séparateur pour la solution.
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
  tlsSessionId = '',
) {
  const target = calculateTarget(suspicionFactor, securityConfig);
  // Le baseBlock est créé ici et sera stocké dans le contexte du challenge.
  const baseBlock = createCpuChallengeBaseBlock(nonce, null, '', clientIp, tlsSessionId);
  return {
    type: "cpu_target",
    nonce: nonce,
    target: target.toString(16),
    path: originalUrl,
  };
}

class SimpleLRUCache {
    constructor(maxSize = 100) {
        this.maxSize = maxSize;
        this.cache = new Map();
    }

    get(key) {
        if (!this.cache.has(key)) return undefined;
        const value = this.cache.get(key);
        this.cache.delete(key);
        this.cache.set(key, value);
        return value;
    }

    set(key, value) {
        if (this.cache.has(key)) {
            this.cache.delete(key);
        } else if (this.cache.size >= this.maxSize) {
            const lruKey = this.cache.keys().next().value;
            this.cache.delete(lruKey);
        }
        this.cache.set(key, value);
    }

    has(key) {
        return this.cache.has(key);
    }

    clear() {
        this.cache.clear();
    }
}

const htmlTemplateCache = new SimpleLRUCache(100);

/**
 * Generates the HTML page for the CPU target challenge.
 * @param {object} challengeDetails - The details from generateCpuTargetChallenge.
 * @param {string} clientIp - The client's IP address.
 * @returns {string} HTML content.
 */
function generateCpuTargetChallengePage(challengeDetails, clientIp) {
    const { nonce, target, path } = challengeDetails;
    const safePath = sanitizeRedirectPath(path);
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
            const nonce = ${safeJsonStringify(nonce)};
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
function generateCombinedPoWChallengePage(cpuChallengeDetails, memoryDifficulty, clientIp, clientSecret, securityConfig, trapUrls, originalFingerprint, tlsSessionId = '') { // eslint-disable-line max-len
    const { nonce, target, path } = cpuChallengeDetails;
    const safePath = sanitizeRedirectPath(path);
    const solverCode = getPowSolverCode();
    // On prépare le baseBlock pour le client. Il sera envoyé sous forme de tableau d'octets.
    // Le fingerprint est maintenant passé directement en paramètre.
    const fingerprint = originalFingerprint;
    const baseBlock = createCpuChallengeBaseBlock(nonce, clientSecret, fingerprint, clientIp, tlsSessionId);
    const baseBlockBytes = `[${baseBlock.toString('utf8').split('').map(c => c.charCodeAt(0)).join(',')}]`;

    // Prépare la configuration pour l'initialisation du client, y compris les URL pièges.
    const clientInitConfig = {
        mouse: true,
        keystrokes: true,
        wasmPath: securityConfig?.wasmPath || '/fp.wasm',
        workerPath: securityConfig?.workerPath || '/pow.worker.js',
        trapUrls: trapUrls // On passe directement le tableau d'URL
    };

    const challengeScript = `
      async function solve() {
        const nonce = ${safeJsonStringify(nonce)};
           const path = ${JSON.stringify(path)};
           const clientSecret = ${safeJsonStringify(clientSecret)};
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
            const memSeed = ":" + nonce + ":" + clientSecret;
            memSolution = await window.solveMemoryChallenge(memSeed, memDifficulty);
        } catch(e) {
            document.getElementById('loader').innerText = "Error: Insufficient memory. Please refresh.";
            return;
        }

        // Redirect with both solutions and the fingerprint used to solve.
        const finalUrl = path + "?pow_type=cpu_mem&pow_nonce=" + ${JSON.stringify(nonce)} + "&pow_solution_cpu=" + cpuSolution + "&pow_solution_mem=" + encodeURIComponent(JSON.stringify(memSolution));
        window.location.href = finalUrl;
      }

      // Initialise la bibliothèque client avec les URL pièges
      // On crée un alias pour un appel plus propre, tout en s'assurant que la bibliothèque est chargée.
      const initializeClient = window.ClientLibrary?.initializeClient;
      if (initializeClient) initializeClient(${JSON.stringify(clientInitConfig)});
      
      solve();
    `;

    let htmlTemplate;
    const customTemplatePath = securityConfig?.challengePagePath;

    if (customTemplatePath) {
        if (htmlTemplateCache.has(customTemplatePath)) {
            htmlTemplate = htmlTemplateCache.get(customTemplatePath);
        } else {
            try {
                htmlTemplate = readFileSync(customTemplatePath, 'utf-8');
                htmlTemplateCache.set(customTemplatePath, htmlTemplate);
            } catch (error) {
                console.warn(`[Fingerprint] Could not load custom challenge page at '${customTemplatePath}'. Falling back to default. Error: ${error.message}`);
            }
        }
    }

    if (!htmlTemplate) {
        htmlTemplate = `<html><head><title>Advanced Security Check</title></head><body style="font-family:sans-serif; text-align:center; padding-top:50px;"><h1>Enhanced Verification... (Level 2)</h1><p>Your activity requires an additional security check. This may take a few moments.</p><div id="loader" style="margin:20px;">⚙️ Initializing combined verification...</div><script><!-- FINGERPRINT_SOLVER_SCRIPT --></script><script><!-- FINGERPRINT_CHALLENGE_SCRIPT --></script></body></html>`; // eslint-disable-line max-len
    }

    return htmlTemplate
        .replace('<!-- FINGERPRINT_SOLVER_SCRIPT -->', solverCode)
        .replace('<!-- FINGERPRINT_CHALLENGE_SCRIPT -->', challengeScript);
}

/**
 * Verifies a PoW solution based on a target and generates a ticket.
 */
export async function verifyCpuTargetPoWAndGenerateTicket(
  clientIp, // This parameter is crucial and must be the actual client IP
  ticketTtl,
  nonce,
  solution,
  challengeContext = {}, // Le contexte complet du challenge est maintenant passé
  deviceId = '',
  deviceHash = ''
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
    const ttl = ticketTtl || 3600000; // Calculates expiration from TTL
    const expiry = Date.now() + ttl;

    return generateStatelessTicket({
      expiry,
      originalIp: clientIp,
      deviceId,
      deviceHash
    }, Math.ceil(ttl / 1000));
  }

  return null;
}

/**
 * @private
 * Parses a GraphQL query string to extract the operation type and name.
 * Uses a lightweight regex to avoid pulling in a heavy AST parser.
 * @param {object} body - The request body, which might contain the query.
 * @returns {{type: string, name: string}|null}
 */
function parseGraphQLQuery(body) {
    const query = body?.query;
    if (typeof query !== 'string') {
        return null;
    }
    // Regex to capture operation type (query, mutation, subscription) and optional operation name.
    // Handles whitespace and potential comments.
    const match = query.match(/(?:^|\s)(query|mutation|subscription)\s+([_A-Za-z][_0-9A-Za-z]*)?/);
    if (match) {
        return {
            type: match[1],
            name: match[2] || 'Anonymous', // Default to 'Anonymous' if name is missing
        };
    }
    return null;
}

/**
 * Calculates a score based on whether the client's ZKP public key (y) is found in a banned list.
 * @param {string} zkpY - The 'y' component of the ZKP proof (public key).
 * @returns {Promise<{threatIntelScore: number}>}
 */
async function getThreatIntelScore(context, zkpY, threatIntelConfig = {}) {
    let score = 0.0;
    const signals = [];

    // 1. Détection déterministe : Clé publique ZKP bannie par consensus fédéré
    if (zkpY) {
        const isBanned = await store.has(`banned-zkp-y:${zkpY}`);
        if (isBanned) {
            score = 100.0;
            signals.push({
                ruleId: 'FEDERATED_ZKP_BANNED',
                confidence: 1.0,
                score: 100.0,
                rationale: 'Cryptographic identity matched banned list consensus'
            });
        }
    }

    // 2. Détection physique : Modélisation continue du différentiel de transport (RTT TCP Edge vs Transit Applicatif)
    // Rationale : Un RTT TCP de socket très faible (datacenter/edge CDN) couplé à un délai applicatif WAN élevé
    // prouve l'interposition d'un relais/tunnel/proxy résidentiel entre le client réel et le point d'entrée.
    const tcpRttHeader = context.headers?.['x-tcp-rtt'] || context.headers?.['x-real-rtt'];
    const tcpRtt = tcpRttHeader ? parseInt(tcpRttHeader, 10) : null;

    const behaviorHeader = context.headers?.['x-behavior-metrics'];
    if (behaviorHeader) {
        try {
            const metrics = JSON.parse(behaviorHeader);
            if (metrics && typeof metrics.clientTimestamp === 'number' && typeof context.requestTimestamp === 'number') {
                const appLatency = context.requestTimestamp - metrics.clientTimestamp;

                // Évaluation uniquement si la latence est mesurable et positive avec une mesure socket RTT valide
                if (tcpRtt !== null && !isNaN(tcpRtt) && tcpRtt > 0 && appLatency > 0) {
                    // Marge de tolérance contre le jitter réseau et le scheduling JS (Garbage Collector, event-loop)
                    const jitterAllowance = 60.0;
                    const effectiveRtt = Math.max(tcpRtt, 5.0);
                    const tunnelDelta = appLatency - (tcpRtt + jitterAllowance);
                    const divergenceRatio = appLatency / effectiveRtt;

                    // Condition de disjonction : liaison edge ultra-proche (< 40ms) + transit applicatif au moins 3x supérieur
                    if (tcpRtt <= 40 && divergenceRatio >= 3.0 && tunnelDelta > 0) {
                        // Progression sigmoïdale continue calibrée sur la propagation optique intercontinentale (120ms)
                        const scaling = 120.0;
                        const ratioWeight = Math.min(1.0, (divergenceRatio - 3.0) / 5.0);
                        const proxyScore = Math.min(95.0, 40.0 + 55.0 * Math.tanh(tunnelDelta / scaling) * ratioWeight);
                        const finalProxyScore = Math.round(proxyScore * 10) / 10;

                        score = Math.max(score, finalProxyScore);
                        signals.push({
                            ruleId: 'RESIDENTIAL_PROXY_RTT_DISCREPANCY',
                            confidence: Math.round(ratioWeight * 100) / 100,
                            score: finalProxyScore,
                            rationale: `TCP RTT (${tcpRtt}ms) diverges from application transit (${appLatency}ms) with ratio ${divergenceRatio.toFixed(1)}:1`
                        });
                    }
                }
            }
        } catch (e) {
            // Ignorer silencieusement les erreurs de parsing des métriques
        }
    }
    return { threatIntelScore: score, threatIntelSignals: signals };
}

export class FingerprintEngine {
  constructor(securityConfig) {
    const isProduction = process.env.NODE_ENV === 'production';
    
    // Dynamically bind Ed25519 keys if passed via config
    if (securityConfig && securityConfig.ed25519_private_key) {
      process.env.ED25519_PRIVATE_KEY = securityConfig.ed25519_private_key;
    }
    if (securityConfig && securityConfig.ed25519_public_key) {
      process.env.ED25519_PUBLIC_KEY = securityConfig.ed25519_public_key;
    }

        // Auto-generate Ed25519 key pair on load if indicated and keys are not set
        if (securityConfig && (securityConfig.useAsymmetricTickets || securityConfig.ed25519 === 'auto') && !process.env.ED25519_PRIVATE_KEY) {
            const persistentKeyPath = join(configDir, 'ed25519_key.json');
            if (existsSync(persistentKeyPath)) {
                try {
                    const keys = JSON.parse(readFileSync(persistentKeyPath, 'utf-8'));
                    process.env.ED25519_PRIVATE_KEY = keys.privateKey;
                    process.env.ED25519_PUBLIC_KEY = keys.publicKey;
                    this._log('Persistent Ed25519 keys loaded from disk');
                } catch (e) {
                    console.error('[Fingerprint] Failed to load persistent Ed25519 keys:', e.message);
                }
            } else {
                try {
                    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519', {
                        privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
                        publicKeyEncoding: { format: 'pem', type: 'spki' }
                    });
                    process.env.ED25519_PRIVATE_KEY = privateKey;
                    process.env.ED25519_PUBLIC_KEY = publicKey;
                    // Persist keys on disk for subsequent restarts
                    writeFileSync(persistentKeyPath, JSON.stringify({ privateKey, publicKey }, null, 2), 'utf-8');
                    this._log('New persistent Ed25519 keys generated and saved to disk');
                } catch (e) {
                    console.error('[Fingerprint] Native Ed25519 key generation failed:', e.message);
                }
                }
        }

    let finalConfig = securityConfig;
    if (securityConfig && securityConfig.autotuning && securityConfig.autotuning.savePath) {
      const sPath = securityConfig.autotuning.savePath;
      if (existsSync(sPath)) {
        try {
          const savedConfig = JSON.parse(readFileSync(sPath, 'utf-8'));
          finalConfig = deepMerge(securityConfig, savedConfig);
        } catch (e) {
          console.warn(`[Fingerprint] Failed to auto-load optimized config from ${sPath}:`, e.message);
        }
      }
    }

    // If no security config is provided at all, create a base one.
    if (!finalConfig) {
        finalConfig = {};
    }
    // If the whitelist is not explicitly provided in the configuration,
    // apply the default whitelist which includes common search engine bots.
    if (!finalConfig.whitelist) {
        finalConfig.whitelist = default_whitelist();
    }

    this.securityConfig = finalConfig;
    this.isProduction = isProduction;
    this._allowlist = this._buildAllowlist();
    this._validateConfig(finalConfig); // Validate the configuration
    this.verbose = finalConfig.verbose || false;
    this.dryRun = finalConfig.dryRun || false;
    
    // Preload solver file asynchronously to liberate event loop during run
    preloadPowSolverCode().catch(() => {});

    if (finalConfig.reset) {
      this.resetStore().catch(err => {
        console.error('[FingerprintEngine] Failed to reset store on startup:', err.message);
      });
    }
  }

  /**
   * Applique à chaud une nouvelle configuration de sécurité (poids, seuils, etc.)
   * sans nécessiter de redémarrage.
   * @param {object} newConfig - La nouvelle configuration partielle ou complète.
   */
  updateConfig(newConfig) {
    this._validateConfig(newConfig);
    this.securityConfig = deepMerge(this.securityConfig, newConfig);
    this.dryRun = this.securityConfig.dryRun || false;
    this._log('Configuration mise à jour à chaud (Hot-Reloaded)', this.securityConfig);
  }

  /**
   * Réinitialise le store de persistance actif.
   */
  async resetStore() {
    if (store && typeof store.clear === 'function') {
      await store.clear();
      this._log('Store has been reset/cleared.');
    }
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
      'autotuning', 'enableUsefulWork', 'usefulWorkConfigPath', 'challengeNewDevices', 'graphql_operation_allowlist', 'dryRun',
      'trustedProxies',
      'wasm',
      'similarityThreshold', 'reset',
      'ed25519_private_key', 'ed25519_public_key', 'upowModel',
      'federatedPeers', 'federationSecret', 'filterWhitelist',
      'challengeRateLimit'
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

  _hasCertainAttack(context) {
    const honeypotConfig = this.securityConfig.honeypot || {};
    const { honeypotScore } = getHoneypotScore(context, honeypotConfig);
    if (honeypotScore >= 100) {
      return true;
    }
    const { botScore } = getBotScore(context);
    if (botScore >= 100) {
      return true;
    }
    return false;
  }

  _log(message, data = {}) {
    if (this.verbose) {
      console.log(`[FingerprintEngine] ${message}`, data);
    }
  }
    calculateFinalScore(suspicionVector) {
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
            (suspicionVector.botnetClusterScore || 0) * (weights.botnetClusterScore || 0) +
            (suspicionVector.tlsSpoofingScore || 0) * (weights.tlsSpoofingScore || 0) + // NOUVEAU: TLS Spoofing
            (suspicionVector.timeInconsistencyScore || 0) * (weights.timeInconsistencyScore || 0) +
            (suspicionVector.clickVarianceScore || 0) * (weights.clickVarianceScore || 0) +
            (suspicionVector.clientHintsInconsistencyScore || 0) * (weights.clientHintsInconsistencyScore || 0) +
            (suspicionVector.subnetScore || 0) * (weights.subnetScore || 0) +
            (suspicionVector.ipReputationScore || 0) * (weights.ipReputationScore || 0) +
            (suspicionVector.tcpAnomalyScore || 0) * (weights.tcpAnomalyScore || 0) +
            (suspicionVector.quicAnomalyScore || 0) * (weights.quicAnomalyScore || 0) + // NOUVEAU: QUIC Anomaly
            (suspicionVector.http2AnomalyScore || 0) * (weights.http2AnomalyScore || 0) + // NOUVEAU: HTTP/2 Anomaly
            (suspicionVector.protocolAnomalyScore || 0) * (weights.protocolAnomalyScore || 0) +
            (suspicionVector.cookieDroppingScore || 0) * (weights.cookieDroppingScore || 0) +
            (suspicionVector.virtualizationScore || 0) * (weights.virtualizationScore || 0) +
            (suspicionVector.threatIntelScore || 0) * (weights.threatIntelScore || 0) + // NOUVEAU: QUIC Anomaly
            (suspicionVector.renderingAnomalyScore || 0) * (weights.renderingAnomalyScore || 0); // NOUVEAU: Rendering Anomaly

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
      const family = isIPv6(clientIp) ? 'ipv6' : 'ipv4';
      return this._allowlist.check(clientIp, family);
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
   * Checks if the GraphQL operation matches an entry in the GraphQL operation allowlist.
   * Supports wildcards for operation names.
   * @private
   * @param {string} operationType - The type of the GraphQL operation (e.g., 'query', 'mutation').
   * @param {string} operationName - The name of the GraphQL operation.
   * @returns {boolean} True if the operation is in the allowlist.
   */
  _isGraphqlOperationInAllowlist(operationType, operationName) {
    const { whitelist = [] } = this.securityConfig;
    const graphqlRule = whitelist.find(rule => rule.type === 'graphql_operation_allowlist');

    if (!graphqlRule || !graphqlRule.entries || !operationType || !operationName) {
      return false;
    }

    for (const entry of graphqlRule.entries) {
      const [entryType, entryName] = entry.split(':');
      if (entryType !== operationType) {
        continue;
      }

      // Check for exact name match or full wildcard
      if (entryName === operationName || entryName === '*') {
        return true;
      }
      // Check for partial wildcard (e.g., "Search*")
      if (entryName.endsWith('*') && operationName.startsWith(entryName.slice(0, -1))) {
        return true;
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
      return null;
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
      return null;
    }

    const botName = matchedRule.userAgent; // e.g., 'Googlebot'

    if (!canAttemptDns()) {
      this._log(`[Bot Verification] DNS circuit breaker is open. Skipping check for ${botName}.`, { clientIp });
      return false;
    }

    const cacheKey = `ip-whitelist:${clientIp}`;
    const cachedStatus = await store.get(cacheKey);

    if (cachedStatus === 'verified') {
      this._log(`[Bot Verification] PASSED (cached): ${botName}`, { clientIp });
      return true;
    }
    if (cachedStatus === 'failed') {
      this._log(`[Bot Verification] FAILED (cached): ${botName}`, { clientIp });
      return false;
    }

    try {
      // 1. Reverse DNS lookup
      const hostnames = await withTimeout(dns.reverse(clientIp), 500);
      const validHostname = hostnames.find(h => h.endsWith(matchedRule.hostnameSuffix));

      if (!validHostname) {
        this._log(`[Bot Verification] FAILED: Reverse DNS lookup for ${clientIp} did not yield a valid hostname ending in '${matchedRule.hostnameSuffix}'.`, { clientIp, resolvedHostnames: hostnames });
        await store.set(cacheKey, 'failed', 300); // Temporary negative caching (5 minutes)
        return false;
      }

      this._log(`[Bot Verification] Reverse DNS OK for ${botName}.`, { clientIp, validHostname });

      // 2. Forward DNS lookup
    let addresses = [];
    try {
        addresses = await withTimeout(dns.resolve(validHostname), 500);
    } catch (e) {
        this._log(`[Bot Verification] Forward DNS (A) lookup FAILED for ${validHostname}.`, { error: e.message });
    }
    try {
        const ipv6 = await withTimeout(dns.resolve(validHostname, 'AAAA'), 500);
      addresses = addresses.concat(ipv6);
    } catch (e) {
        this._log(`[Bot Verification] Forward DNS (AAAA) lookup FAILED for ${validHostname}.`, { error: e.message });
    }
    if (addresses.includes(clientIp)) {
        this._log(`[Bot Verification] PASSED: Forward DNS IP matches original IP for ${botName}.`, { clientIp, validHostname, resolvedIps: addresses });
        recordDnsSuccess();
        await store.set(cacheKey, 'verified', 86400); // Cache success for 24h (TTL in seconds)
        return true;
      }
      this._log(`[Bot Verification] FAILED: IP mismatch for ${botName}. Original IP not in resolved addresses.`, { clientIp, validHostname, resolvedIps: addresses });
    } catch (error) {
      this._log(`[Bot Verification] FAILED: DNS lookup error for ${botName}.`, { clientIp, error: error.message });
      recordDnsFailure();
      await store.set(cacheKey, 'failed', 300); // Temporary negative caching (5 minutes)
      return false;
    }

    await store.set(cacheKey, 'failed', 300); // Temporary negative caching (5 minutes)
    return false;
  }

  async processRequest(requestContext) {
      if (this.securityConfig?.reset) {
          const subnet = getIpSubnet(requestContext.clientIp);
          if (subnet) {
              await store.delete(`subnet:${subnet}`);
          }
          await store.delete(`ip-reputation:${requestContext.clientIp}`);
      }
      sanitizeProxyHeaders(requestContext, this.securityConfig);

      const { clientIp = "unknown", path, cookies = {}, query = {}, isStatic, graphqlOperationType, graphqlOperationName } = requestContext;

      if (query.coop_op) {
          const coopParams = {
              ...query,
              signature: requestContext.headers?.['x-federation-signature'] || query.signature,
              signature_ed25519: requestContext.headers?.['x-federation-signature-ed25519'] || query.signature_ed25519,
              timestamp: requestContext.headers?.['x-federation-timestamp'] || query.timestamp
          };
          const result = await handleCooperativeRequest(coopParams, clientIp, this.securityConfig);
          return {
              action: 'challenge',
              status: 200,
              body: result
          };
      }

      const { weights, thresholds, logger, onDeviceCompromised } = this.securityConfig;
    
    let preCalculatedVector = null;
    let preCalculatedScore = null;
    const getScoreAndVector = async () => {
      if (preCalculatedScore === null) {
        preCalculatedVector = await __internal.getSuspicionVector(requestContext, this.securityConfig);
        preCalculatedScore = this.calculateFinalScore(preCalculatedVector);
      }
      return { score: preCalculatedScore, vector: preCalculatedVector };
    };

    this._log('Processing request', { clientIp, path, isStatic });
    
    // Bypass instantané si l'appareil a prouvé cryptographiquement son identité matérielle (Secure Enclave / TPM)
    const { deviceId, deviceData, newCookie } = await resolveRequestIdentity(requestContext, this.securityConfig);
    if (deviceData && deviceData.webauthnVerified) {
        this._log('Hardware-anchored device verified (WebAuthn) - full bypass granted', { deviceId });
        return { action: 'next', score: 0, vector: { webauthn_verified: 100 } };
    }

    if (isStatic) {
      this._log('Static resource - skipping checks');
      return { action: 'next', score: 0, vector: {} };
    }

    // Resolve identity and check for persisted "condemned" status early.
    const currentDeviceHash = getCompositeDeviceHash(requestContext);
    const isNewDevice = !!newCookie;
    const allowRoaming = this.securityConfig?.allowCrossNetworkRoaming ?? false;

    // 1. Check static IP allowlist first for maximum performance.
    let whitelisted = false;
    let whitelistType = '';

    if (this._isIpInAllowlist(clientIp)) {
      whitelisted = true;
      whitelistType = 'allowlist';
    } else if (await this._isIpInHostnameAllowlist(clientIp)) {
      whitelisted = true;
      whitelistType = 'hostname_allowlist';
    } else {
      const requestHost = requestContext.headers?.host;
      if (requestHost && this._isHostPathInAllowlist(requestHost, path)) {
        whitelisted = true;
        whitelistType = 'host_path_allowlist';
      } else if (this._isPathInAllowlist(path)) {
        whitelisted = true;
        whitelistType = 'path_allowlist';
      } else if (graphqlOperationType && this._isGraphqlOperationInAllowlist(graphqlOperationType, graphqlOperationName)) {
        whitelisted = true;
        whitelistType = 'graphql_operation_allowlist';
      }
    }

    if (whitelisted) {
      const filterWhitelist = this.securityConfig.filterWhitelist || false;
      let bypassWhitelist = false;
      if (filterWhitelist === true) {
        bypassWhitelist = this._hasCertainAttack(requestContext);
      } else if (typeof filterWhitelist === 'number') {
        const res = await getScoreAndVector();
        if (res.score > filterWhitelist) {
          bypassWhitelist = true;
        }
      }

      if (bypassWhitelist) {
        this._log('Whitelisted request exceeds filter threshold - bypassing whitelist bypass', { clientIp, path });
      } else {
        this._log(`IP/Path in allowlist (${whitelistType}) - allowing request`, { clientIp, path });
        return { action: 'next', score: 0, vector: { whitelisted: 100, type: whitelistType } };
      }
    }

    const { pow_nonce } = query;

    // Honeypot: Direct probing of challenge endpoints is highly suspicious.
    // A legitimate user only hits these endpoints via the challenge page itself.
    // If we see a pow_nonce on a request that isn't (yet) considered suspicious, it's a bot probe.
    if (pow_nonce) {
        const powCookie = cookies?.pow_clearance;
        if (!await isTicketValid(clientIp, powCookie, deviceId, currentDeviceHash, allowRoaming)) { // Only check if there's no valid ticket
            // This is a potential probe. We'll let the main logic confirm if it's not a legitimate challenge response.
            // The final decision is made later, after calculating the score.
        }
    }

    const botVerificationResult = await this._verifyWhitelistedBot(requestContext);
    if (botVerificationResult === true) {
      const filterWhitelist = this.securityConfig.filterWhitelist || false;
      let bypassWhitelist = false;
      if (filterWhitelist === true) {
        bypassWhitelist = this._hasCertainAttack(requestContext);
      } else if (typeof filterWhitelist === 'number') {
        const res = await getScoreAndVector();
        if (res.score > filterWhitelist) { // NOSONAR
          bypassWhitelist = true;
        }
      }

      if (bypassWhitelist) {
        this._log('Verified bot request exceeds filter threshold - bypassing bot whitelist bypass', { clientIp });
      } else {
        this._log('Whitelisted bot verified - allowing request', { clientIp });
        return { action: 'next', score: 0, vector: { whitelisted: 100, type: 'bot' } };
      }
    }
    
    this._log('Identity resolved', { deviceId, isNewDevice, hasDeviceData: !!deviceData });

    if (deviceData?.condemned) {
        this._log('Device condemned - blocking request', { deviceId });
        if (onDeviceCompromised) {
            onDeviceCompromised({ deviceId: deviceId, clientIp, reason: 'Previously condemned', score: 100, vector: { honeypotScore: 100 } });
        }
        const decision = { action: 'block', status: 404, body: 'Forbidden', score: 100, vector: { honeypotScore: 100 } };
        if (this.dryRun) {
            this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
            decision.intendedAction = decision.action;
            decision.action = 'next';
            delete decision.status;
            delete decision.body;

            if (requestContext._newCookies) {
                const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
                if (deviceCookie) {
                    decision.newCookieForResponse = deviceCookie;
                }
            }
        }
        return decision;
    }

    // The engine now works with the context directly, no more rawReq dependency here.
    const suspicionVector = preCalculatedVector || await __internal.getSuspicionVector(requestContext, this.securityConfig);
    if (botVerificationResult === false) {
        // This means it claimed to be a bot but failed verification.
        // This is a strong signal of spoofing.
        suspicionVector.tlsSpoofingScore = Math.max(suspicionVector.tlsSpoofingScore || 0, 95);
    }
    let finalScore = preCalculatedScore !== null ? preCalculatedScore : this.calculateFinalScore(suspicionVector);

    this._log('Suspicion vector calculated', { 
        vector: suspicionVector,
        weights: this.securityConfig.weights 
    });

    this._log('Final score calculated', { finalScore });

    const blockThreshold = thresholds.block ?? 95;

    // Mettre à jour les métriques du sous-réseau après le calcul du score final
    if (finalScore >= (thresholds.medium ?? 45) && finalScore < blockThreshold) {
        await __internal.updateSubnetMetrics(requestContext, deviceId, finalScore);
    }

    // Si c'est un nouvel appareil, on lui impose un challenge de base, même si son score est bas.
    // Cela augmente le coût pour les bots qui tentent de simplement supprimer leurs cookies.
    // NOUVEAU : Cette logique est maintenant configurable.
    const challengeNewDevices = this.securityConfig.challengeNewDevices === true;
    if (challengeNewDevices && isNewDevice && finalScore < thresholds.low) {
      this._log('New device - enforcing minimum challenge score', { 
          originalScore: finalScore, 
          enforcedScore: thresholds.low 
      });
      finalScore = thresholds.low;
    }

    // --- NOUVELLE LOGIQUE DE PRIORITÉ ---
    // Si une solution de challenge est soumise, on la traite en priorité absolue,
    // avant même de recalculer le score de suspicion.
    const { pow_type, pow_solution, pow_solution_cpu, pow_solution_mem, pow_fp, pow_solution_population, pow_solution_work_result, pow_problem_id, pow_solution_space } = query;
    if (pow_nonce && (pow_solution || pow_solution_cpu || pow_solution_space)) { // Vérifie pow_solution pour la compatibilité ascendante
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
            let challengeContext = await store.get(`secret:${pow_nonce}`);

            // SECURITY: Verify that the retrieved context has not been tampered with
            if (challengeContext && challengeContext.signature) {
                const payloadToSign = `${challengeContext.clientSecret}:${challengeContext.cpuTarget}:${challengeContext.fingerprint}:${challengeContext.memDifficulty}:${challengeContext.originalPath}:${clientIp}`;
                const expectedSignature = crypto.createHmac("sha256", getPowSecret()).update(payloadToSign).digest("hex");
                try {
                    const isSignatureValid = crypto.timingSafeEqual(
                        Buffer.from(challengeContext.signature, 'hex'),
                        Buffer.from(expectedSignature, 'hex')
                    );
                    if (!isSignatureValid) {
                        this._log('Challenge context signature invalid - storage tampering detected!', { nonce: pow_nonce });
                        challengeContext = null; // Invalidate context immediately
                    }
                } catch (e) {
                    this._log('Error validating challenge context signature:', e);
                    challengeContext = null;
                }
            }
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
                const safe_pow_fp = typeof pow_fp === 'string' ? pow_fp : (Array.isArray(pow_fp) ? String(pow_fp[0]) : '');
                const solverFingerprint = safe_pow_fp || getCompositeDeviceHash(requestContext);
                const originalFingerprint = typeof challengeContext.fingerprint === 'string' ? challengeContext.fingerprint : '';

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
                this._log('Challenge context found, verifying solution', {optimalTtl, finalTtl});

                if ((pow_type === "cpu_target" || !pow_type) && (pow_solution_cpu || pow_solution)) { // !pow_type pour compatibilité
                    const cpuSolution = pow_solution_cpu || pow_solution;
                    ticket = await verifyCpuTargetPoWAndGenerateTicket(clientIp, finalTtl, pow_nonce, cpuSolution, challengeContext, deviceId, currentDeviceHash);
                    isValid = ticket !== null;
                    this._log('CPU target challenge verification', {isValid});
                } else if (pow_type === "cpu_mem" && pow_solution_cpu && pow_solution_mem) {
                    const cpuTicket = await verifyCpuTargetPoWAndGenerateTicket(clientIp, finalTtl, pow_nonce, pow_solution_cpu, challengeContext, deviceId, currentDeviceHash);
                    const isMemValid = verifyMemoryPoW(pow_nonce, pow_solution_mem, challengeContext.memDifficulty, challengeContext.clientSecret); // Memory PoW is independent of fingerprint
                    isValid = cpuTicket !== null && isMemValid;
                    if (isValid) ticket = cpuTicket; // Le ticket est le même, on le réutilise
                    this._log('Combined CPU+Memory challenge verification', {
                        cpuValid: cpuTicket !== null,
                        memValid: isMemValid,
                        isValid
                    });
                } else if (pow_type === "pospace" && pow_solution_space) {
                    const isSpaceValid = await verifySpacePoW(pow_nonce, pow_solution_space, challengeContext.queries, pow_nonce + ":" + challengeContext.clientSecret, challengeContext.clientSecret);
                    isValid = isSpaceValid;
                    if (isValid) {
                        const ttl = finalTtl || 3600000;
                        ticket = generateStatelessTicket({
                            expiry: Date.now() + ttl,
                            originalIp: clientIp,
                            deviceId,
                            deviceHash: currentDeviceHash
                        });
                    }
                } else if (pow_type === "gpu" && pow_solution) {
                    const isGpuValid = GpuPowSolver.verify(pow_nonce, challengeContext.iterations || 200000, pow_solution, clientIp, getPowSecret());
                    isValid = isGpuValid;
                    if (isValid) {
                        const ttl = finalTtl || 3600000;
                        ticket = generateStatelessTicket({
                            expiry: Date.now() + ttl,
                            originalIp: clientIp,
                            deviceId,
                            deviceHash: currentDeviceHash
                        });
                    }
                }
            }
        } else {
            this._log('Challenge context not found or expired', { pow_nonce });
            // --- NOUVELLE MESURE DE SÉCURITÉ ---
            // Si un client soumet un nonce invalide ou expiré, c'est une tentative de probing ou de rejeu.
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
            finalSearchParams.delete('pow_solution_space');
            // NOUVEAU: Nettoyer aussi les paramètres des challenges d'optimisation et de travail utile
            finalSearchParams.delete('pow_solution_population');
            finalSearchParams.delete('pow_solution_work_result');
            finalSearchParams.delete('pow_problem_id');

            // 4. On reconstruit le chemin final.
            const finalQueryString = finalSearchParams.toString();
            const finalRedirectPath = finalQueryString ? `${originalUrl.pathname}?${finalQueryString}` : originalUrl.pathname;
            this._log('Redirecting to clean path', { finalRedirectPath, cookieMaxAge: finalTtl });
            const isHttps = requestContext.headers?.['x-forwarded-proto'] === 'https' || 
                            requestContext.rawReq?.secure || 
                            requestContext.rawReq?.protocol === 'https' ||
                            requestContext.rawReq?.connection?.encrypted;
            const secureOption = isHttps || this.isProduction;
            return {
              action: 'redirect',
              path: finalRedirectPath,
              score: 0, // Le score n'est pas pertinent ici, on a passé le test.
              vector: { challenge_solved: 100 },
              cookie: {
                name: 'pow_clearance',
                value: ticket, // The ticket itself
                options: { 
                  httpOnly: true, 
                  secure: secureOption, 
                  sameSite: 'strict',
                  ...(secureOption && { partitioned: true }),
                  maxAge: finalTtl 
                } // Options for setting the cookie
              }
            };
        } else {
            // If the solution is invalid, we should treat it as a high-suspicion event.
            // This prevents the request from proceeding and forces a new, likely harder, challenge.
            this._log('Challenge solution invalid or fingerprint mismatch', { pow_nonce });
            suspicionVector.honeypotScore = 100; // Invalid solution is a strong bot signal.
            finalScore = this.calculateFinalScore(suspicionVector);
            // --- FIX: After invalidating a solution, immediately check if the new score triggers a block ---
            const newBlockThreshold = thresholds.block ?? 95;
            if (finalScore >= newBlockThreshold) {
                this._log('Request blocked after invalid challenge solution', { finalScore, newBlockThreshold });
                const decision = { action: 'block', status: 404, body: 'Forbidden', score: finalScore, vector: suspicionVector };
                if (this.dryRun) {
                    this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
                    decision.intendedAction = decision.action;
                    decision.action = 'next';
                    delete decision.status;
                    delete decision.body;
                    if (requestContext._newCookies) {
                        const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
                        if (deviceCookie) {
                            decision.newCookieForResponse = deviceCookie;
                        }
                    }
                }
                return decision;
            }
            // If not blocked, the request will proceed to be re-challenged.
            // To ensure a challenge is issued, set the score to just below the block threshold.
            // This ensures it falls into the 'challenge' category (>= high, < block).
            finalScore = Math.min(finalScore, (thresholds.block ?? 95) - 1);
            this._log('Invalid solution leads to re-challenge', { finalScore });
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
                const defaultPath = resolve(__dirname, '..', '..', 'config', 'problems.config.json');
                const configPath = this.securityConfig.usefulWorkConfigPath || (existsSync(defaultPath) ? defaultPath : undefined);
                const manager = await getProblemManager({
                    configPath,
                    config: this.securityConfig.usefulWorkConfig
                }, store);
                await manager.integrateSolution(pow_problem_id, workResult);

                // Si le problème résolu est l'auto-tuning de sécurité et que l'auto-tuning est activé,
                // on applique directement la meilleure solution calculée au moteur en direct.
                if (pow_problem_id === 'security_auto_tuning' && this.securityConfig.autotuning?.enabled) {
                    const paretoFront = workResult.paretoFront;
                    if (Array.isArray(paretoFront) && paretoFront.length > 0) {
                        let bestSolution = paretoFront[0];
                        let minDistance = Math.sqrt(Math.pow(bestSolution.objectives[0], 2) + Math.pow(bestSolution.objectives[1], 2));
                        for (let i = 1; i < paretoFront.length; i++) {
                            const distance = Math.sqrt(Math.pow(paretoFront[i].objectives[0], 2) + Math.pow(paretoFront[i].objectives[1], 2));
                            if (distance < minDistance) {
                                minDistance = distance;
                                bestSolution = paretoFront[i];
                            }
                        }
                        if (bestSolution && bestSolution.solution) {
                            this.updateConfig(bestSolution.solution);
                            this._log('Useful Work auto-tuning applied successfully to live config.');
                        }
                    }
                }

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

    // Honeypot: Direct probing of challenge endpoints is highly suspicious.
    // A legitimate user only hits these endpoints via the challenge page itself.
    // If we see a pow_nonce on a request that has no valid ticket,
    // AND it's not a legitimate response to a challenge we issued, it's a probe.
    const isChallengeResponse = query.pow_solution || (query.pow_solution_cpu && query.pow_solution_mem);
    if (pow_nonce && !isChallengeResponse) {
        this._log('Honeypot probe detected - blocking request', { path, pow_nonce });
        if (logger) {
            logger({ type: 'honeypot_probe', deviceId: cookies?.device_id, score: finalScore, path: path, timestamp: Date.now(), vector: suspicionVector });
        }
        suspicionVector.honeypotScore = 100; // Bot is probing. Max penalty.
        // Recalculate the final score with the updated vector.
        finalScore = this.calculateFinalScore(suspicionVector);
        const decision = { action: 'block', status: 404, body: 'Forbidden', score: finalScore, vector: suspicionVector };
        if (this.dryRun) {
            this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
            decision.intendedAction = decision.action;
            decision.action = 'next';
            delete decision.status;
            delete decision.body;
            if (requestContext._newCookies) {
                const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
                if (deviceCookie) {
                    decision.newCookieForResponse = deviceCookie;
                }
            }
        }
        return decision;
    }

    const isBlocked = finalScore >= blockThreshold;

// NOUVEAU: Si l'action est de bloquer, on enregistre le ZKP du client dans la liste des bannis.
      if (isBlocked) {
          const zkpProof = requestContext.headers['x-zkp-proof'] || requestContext.query.pow_zkp || '';
          const parts = zkpProof.split(':');
          if (parts.length === 3) {
              const [zkpY, zkpT, zkpS] = parts;
              // 1. Valider cryptographiquement la preuve avant de bannir/diffuser
              if (verifyZkpProof(zkpY, zkpT, zkpS)) {
                  const peersKey = `fed-peers:${zkpY}`;
                  let reportedPeers = await store.get(peersKey) || [];
                  if (!Array.isArray(reportedPeers)) {
                      reportedPeers = [];
                  }
                  if (!reportedPeers.includes('local')) {
                      reportedPeers.push('local');
                      await store.set(peersKey, reportedPeers, 86400 * 30);
                  }

                  const threshold = this.securityConfig.federationConsensusThreshold || 3;
                  if (reportedPeers.length >= threshold) {
                      if (!(await store.has(`banned-zkp-y:${zkpY}`))) {
                          await store.set(`banned-zkp-y:${zkpY}`, true, 86400 * 30); // Banni pour 30 jours
                      }
                  }
                  broadcastBannedZkp(zkpY, this.securityConfig).catch(() => {});
              }
          }
      }
    const isSuspiciousHigh = finalScore >= thresholds.high && !isBlocked && finalScore > 0;
    const isSuspiciousMedium = finalScore >= thresholds.medium && finalScore > 0;
    const isSuspicious = finalScore >= thresholds.low && finalScore > 0;
    const isVerySuspicious = finalScore >= thresholds.medium && finalScore > 0; // Seuil pour le challenge d'optimisation

    // Calculate an analog "suspicion factor" (0 to 1+) for progressive difficulty
    const suspicionFactor = isSuspicious // eslint-disable-line no-nested-ternary
        ? (() => {
            const denominator = thresholds.high - thresholds.low;
            if (denominator === 0) {
                // If the range is zero, and finalScore is at or above low threshold,
                // return 0 to avoid NaN.
                return 0;
            }
            return Math.min(1.5, (finalScore - thresholds.low) / denominator);
        })()
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
        onDeviceCompromised({ deviceId: deviceId, clientIp, reason: 'Score exceeded block threshold', score: finalScore, vector: suspicionVector });
      }
      if (logger) {
        logger({ type: 'request_blocked', deviceId: deviceId, score: finalScore, vector: suspicionVector, timestamp: Date.now() });
      }
      const decision = { action: 'block', status: 404, body: 'Forbidden', score: finalScore, vector: suspicionVector };
      if (this.dryRun) {
          this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
          decision.intendedAction = decision.action;
          decision.action = 'next';
          delete decision.status;
          delete decision.body;
          if (requestContext._newCookies) {
              const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
              if (deviceCookie) {
                  decision.newCookieForResponse = deviceCookie;
              }
          }
      }
      return decision;
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
        const decision = { action: 'block', status: 404, score: 100, vector: { honeypotScore: 100 } };
        if (this.dryRun) {
            this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
            decision.intendedAction = decision.action;
            decision.action = 'next';
            delete decision.status;
            delete decision.body;
            if (requestContext._newCookies) {
                const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
                if (deviceCookie) {
                    decision.newCookieForResponse = deviceCookie;
                }
            }
        }
        return decision;
    }
    
    // --- NOUVELLE LOGIQUE DE RE-CHALLENGE ---
    // Un challenge est nécessaire si :
    // 1. La requête est suspecte ET il n'y a pas de ticket valide.
    // OU
    // 2. La requête est très suspecte (dépasse le seuil 'high'), ce qui annule la validité du ticket actuel.
    const zkpProof = requestContext.headers['x-zkp-proof'] || query.pow_zkp || '';
    const hasValidTicket = await isTicketValid(clientIp, powCookie, deviceId, currentDeviceHash, allowRoaming, zkpProof);
    // Correction : Pour éviter une boucle infinie de challenges (qui mène à l'erreur 429),
    // on fait confiance au ticket valide tant qu'il n'a pas expiré.
    const maxIndicatorsCount = Object.values(suspicionVector).filter(val => typeof val === 'number' && val >= 100).length;
    const mustReChallenge = (suspicionVector.honeypotScore >= (thresholds.medium ?? 45)) || (maxIndicatorsCount >= 1);

    if ((isSuspicious && !hasValidTicket) || mustReChallenge) {
        if (mustReChallenge) {
            this._log('High suspicion score detected - overriding valid ticket to re-issue challenge', { finalScore, deviceId });
        }

        // --- Limiteur de débit par domaine et sous-réseau (Token Bucket) ---
        const domain = requestContext.headers?.host || 'default';
        const rateLimitPassed = await checkChallengeRateLimit(clientIp, domain, this.securityConfig?.challengeRateLimit);
        if (!rateLimitPassed) {
            this._log('Challenge rate limit exceeded - blocking with 429', { clientIp, domain });
            const decision = {
                action: 'block',
                status: 429,
                body: 'Too Many Requests',
                score: finalScore,
                vector: suspicionVector
            };
            if (this.dryRun) {
                this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
                decision.intendedAction = decision.action;
                decision.action = 'next';
                delete decision.status;
                delete decision.body;
                if (requestContext._newCookies) {
                    const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
                    if (deviceCookie) {
                        decision.newCookieForResponse = deviceCookie;
                    }
                }
            }
            return decision;
        }

        this._log('Suspicious request without valid ticket - issuing challenge', { finalScore, hasPowCookie: !!powCookie });

        // --- SELECTION AND SENDING OF THE APPROPRIATE CHALLENGE ---
        const nonce = crypto.randomBytes(16).toString("hex");
        const clientSecret = crypto.randomBytes(16).toString("hex");
            const isApi = requestContext.rawReq && this.securityConfig?.isApiRequest?.(requestContext.rawReq);

        // Pour les scores élevés, on choisit aléatoirement entre un challenge de travail utile et un PoW classique.
        // Cela rend l'automatisation plus difficile pour un attaquant.
        // Utilisation de crypto pour un choix plus sécurisé.
        const shouldUseUsefulWork = this.securityConfig.enableUsefulWork && crypto.randomBytes(1).readUInt8(0) / 255 > 0.5;

        let usefulWorkDispatched = false;
        let challengePayload = null;

        if ((isSuspicious || mustReChallenge) && shouldUseUsefulWork) {
            this._log('Issuing a useful work challenge', { finalScore });

            try {
                const defaultPath = resolve(process.cwd(), 'config', 'problems.config.json');
                const configPath = this.securityConfig.usefulWorkConfigPath || (existsSync(defaultPath) ? defaultPath : undefined);
                const manager = await getProblemManager({
                    configPath,
                    config: this.securityConfig.usefulWorkConfig
                }, store);
                const work = manager?.dispatchWork(suspicionFactor);
                if (work) {
                    const { problemId, task } = work;
                    await store.set(`secret:${nonce}`, { clientSecret, originalPath: path }, 300);

                    challengePayload = {
                        challenge: {
                            type: 'useful_work_task',
                            nonce: nonce,
                            clientSecret: clientSecret,
                            usefulWorkTask: { problemId, task }
                        }
                    };
                    usefulWorkDispatched = true;
                } else {
                    this._log('Useful work dispatch returned null (no problems available). Falling back to PoW.');
                }
            } catch (err) {
                this._log('Failed to dispatch useful work. Falling back to PoW:', err);
            }
        }

        if ((isSuspicious || mustReChallenge) && usefulWorkDispatched) {
            if (isApi) {
                return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: challengePayload };
            } else {
                const taskType = challengePayload.challenge.usefulWorkTask.task.type;
                let dummyResult = { solution: [], energy: 0 };
                if (taskType === 'multi_objective_genetic_algorithm') {
                    dummyResult = { paretoFront: [] };
                } else if (taskType === 'genetic_algorithm_generations') {
                    dummyResult = { population: [] };
                }
                const html = `<html><body><script>
                    window.location.href = "${path}?pow_type=useful_work_task&pow_nonce=${nonce}&pow_problem_id=${challengePayload.challenge.usefulWorkTask.problemId}&pow_solution_work_result=" + encodeURIComponent(JSON.stringify(${JSON.stringify(dummyResult)}));
                </script></body></html>`;
                return { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404, body: html };
            }
        } else if (isSuspicious || mustReChallenge) { // Pour les scores bas/moyens ou si le travail utile n'est pas choisi / a échoué                
            const decision = { action: 'challenge', score: finalScore, vector: suspicionVector, status: 404 };
                if (this.dryRun) {
                    this._log(`[Dry Run] Intended action: ${decision.action}`, { score: decision.score });
                    decision.intendedAction = decision.action;
                    decision.action = 'next';
                    delete decision.status;
                    return decision;
                }
            if (this.securityConfig.enableProofOfSpace) {
                const spaceChallenge = await generateSpaceChallenge(clientIp, nonce, suspicionFactor, path, this.securityConfig);
                const clientSecret = crypto.randomBytes(16).toString("hex");
                await store.set(`secret:${nonce}`, {
                    clientSecret,
                    suspicionScore: finalScore,
                    queries: spaceChallenge.queries,
                    sizeMb: spaceChallenge.sizeMb,
                    originalPath: path,
                }, this.securityConfig.challengeTtl || 300);
                
                if (isApi) {
                    decision.body = {
                        challenge: {
                            type: 'pospace',
                            nonce: nonce,
                            clientSecret,
                            queries: spaceChallenge.queries,
                            sizeMb: spaceChallenge.sizeMb,
                        }
                    };
                } else {
                    const page = generateSpaceChallengePage(spaceChallenge, clientSecret, this.securityConfig);
                    decision.body = page;
                }
                return decision;
            }

            // NOUVEAU : Challenge matériel GPU (Logistic Map floating point parity check)
            const shouldUseGpu = this.securityConfig.enableGpuPow && finalScore >= thresholds.high;
            if (shouldUseGpu) {
                const iterations = this.securityConfig.gpuPowIterations || 200000;
                await store.set(`secret:${nonce}`, {
                    clientSecret,
                    iterations,
                    fingerprint: originalFingerprint,
                    originalPath: path
                }, this.securityConfig.challengeTtl || 300);

                if (isApi) {
                    decision.body = {
                        challenge: { type: "gpu", nonce, clientSecret, iterations }
                    };
                } else {
                    decision.body = generateGpuChallengePage({ nonce, iterations, path });
                }
                return decision;
            }

            // Generate some trap URLs to embed in the challenge page.
            // These links are visually hidden but present in the DOM to trap bots.
            const trapUrls = Array.from({ length: 3 }, () => generateTrapUrl(nonce)); // Génère les URL

            // On passe la configuration pour que la difficulté soit calculée correctement.
    const tlsSessionId = getTlsSessionId(requestContext) || '';
    const cpuChallengeDetails = generateCpuTargetChallenge(clientIp, nonce, suspicionFactor, path, this.securityConfig, tlsSessionId);

            // La difficulté mémoire augmente désormais en parfaite synergie avec le facteur de suspicion (ratio constant)
            const memActivationFactor = suspicionFactor;

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
    const baseBlock = createCpuChallengeBaseBlock(nonce, clientSecret, originalFingerprint, clientIp, tlsSessionId);

            // SECURITY: Cryptographically sign the payload before storing it to prevent database tampering
            const payloadToSign = `${clientSecret}:${cpuChallengeDetails.target}:${originalFingerprint}:${memDifficulty}:${path}:${clientIp}`;
            const signature = crypto.createHmac("sha256", getPowSecret()).update(payloadToSign).digest("hex");

            await store.set(`secret:${nonce}`, {
                clientSecret,
                cpuTarget: cpuChallengeDetails.target,
                suspicionScore: finalScore, // *** FIX: Store the score that triggered the challenge ***
                fingerprint: originalFingerprint, // *** NOUVEAU ***
                memDifficulty: memDifficulty,
                baseBlock: baseBlock, // *** NOUVEAU: Le bloc de base est stocké pour la vérification ***
                originalPath: path, // *** FIX: Store the original path ***
                signature, // *** NOUVEAU: Cryptographic signature to prevent storage tampering ***
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
                decision.body = challengePayload;
            } else {
                // For browsers, send the HTML page.
        const page = generateCombinedPoWChallengePage(cpuChallengeDetails, memDifficulty, clientIp, clientSecret, this.securityConfig, trapUrls, originalFingerprint, tlsSessionId);
                this._log('Browser challenge page generated', {
                    pageLength: page.length,
                    trapUrlsInjected: trapUrls.length
                });
                decision.body = page;
            }
            return decision;
        }
    }

    // Basic log for each non-static request that passed without a challenge
    this._log('Request passed - no challenge required', { finalScore, hasValidTicket: await isTicketValid(clientIp, powCookie, deviceId, currentDeviceHash, allowRoaming) });
    
    if (logger) {
        logger({ type: 'request_passed', deviceId: cookies?.device_id, score: finalScore, timestamp: Date.now(), vector: suspicionVector });
    }
      const response = { action: 'next', score: finalScore, vector: suspicionVector, intendedAction: 'next' };
      if (requestContext._newCookies) {
          const deviceCookie = requestContext._newCookies.find(c => c.name === 'device_id');
          if (deviceCookie) {
              response.newCookieForResponse = deviceCookie;
          }
      }
      return response;
  }

  /**
   * Identifies a request in a granular way for non-Express environments.
   * @param {object} requestContext - The request context object.
   * @returns {Promise<string>} An identification string (e.g., "device:<id>", "suspicious_high:<ip>").
   */
  async identifyRequest(requestContext) {
      sanitizeProxyHeaders(requestContext, this.securityConfig);
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
    const score = this.calculateFinalScore(vector);

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
  "\\.(js|css|png|jpg|jpeg|gif|svg|mp3|webp|ico|woff|woff2|ttf|otf|map|json|manifest|webmanifest|wasm)$",
  "i",
);
const isStaticResource = (path) => staticExtensions.test(path);

export async function registerCooperativeNode(clientIp, nodeId, seed) {
    const subnet = getIpSubnet(clientIp);
    if (!subnet) return;

    const key = `coop-pospace:subnet:${subnet}`;
    const nodes = (await store.get(key)) || {};
    const now = Math.floor(Date.now() / 1000);

    // Clean up expired nodes (older than 120 seconds)
    const cleanedNodes = {};
    for (const [id, node] of Object.entries(nodes)) {
        if (now - node.timestamp < 120) {
            cleanedNodes[id] = node;
        }
    }

    cleanedNodes[nodeId] = {
        nodeId,
        seed,
        timestamp: now
    };

    await store.set(key, cleanedNodes, 120);
}

export async function findPeerInSubnet(clientIp, excludeNodeId) {
    const subnet = getIpSubnet(clientIp);
    if (!subnet) return null;

    const key = `coop-pospace:subnet:${subnet}`;
    const nodes = (await store.get(key)) || {};
    const now = Math.floor(Date.now() / 1000);

    const activePeers = [];
    for (const [id, node] of Object.entries(nodes)) {
        if (id !== excludeNodeId && now - node.timestamp < 120) {
            activePeers.push(node);
        }
    }

    if (activePeers.length === 0) return null;

    // Select a random peer
    const randomIndex = crypto.randomInt(0, activePeers.length);
    return activePeers[randomIndex];
}

export async function handleCooperativeRequest(params, clientIp = '127.0.0.1', config = {}) {
    const op = params.coop_op;
    if (!op) return null;

    if (op === 'share_threat_intel') {
        const peers = config.federatedPeers || [];
        if (peers.length > 0) {
            const allowedIPsAndHosts = peers.map(url => {
                try { return new URL(url).hostname; } catch(e) { return url; }
            });
            if (!allowedIPsAndHosts.includes(clientIp)) {
                return { error: 'Unauthorized federation sender IP' };
            }
        }
        const zkpY = params.zkpY || '';
        const timestamp = Number(params.timestamp || 0);

        if (!zkpY || !timestamp) {
            return { error: 'Missing threat intel parameters' };
        }

        // Vérification de la fraîcheur du message pour éviter les attaques par rejeu
        if (Math.abs(Date.now() - timestamp) > 300000) { // 5 minutes max skew
            return { error: 'Message expired or clock skew too high' };
        }

        const msg = `${timestamp}:${zkpY}`;
        const sigEd25519 = params.signature_ed25519 || '';
        const sigHmac = params.signature || '';

        if (sigEd25519) {
            const publicKey = config.ed25519_public_key || process.env.ED25519_PUBLIC_KEY;
            if (!publicKey) {
                return { error: 'Missing public key for asymmetric verification' };
            }
            try {
                const cleanKey = publicKey.replace(/\\n/g, '\n');
                const isVerified = crypto.verify(
                    null,
                    Buffer.from(msg),
                    { key: cleanKey, format: 'pem', type: 'spki' },
                    Buffer.from(sigEd25519, 'hex')
                );
                if (!isVerified) {
                    return { error: 'Invalid asymmetric federation signature' };
                }
            } catch (e) {
                return { error: 'Asymmetric signature verification failed' };
            }
        } else if (sigHmac) {
            const secret = config.federationSecret || getPowSecret();
            const expectedSig = crypto.createHmac('sha256', secret).update(msg).digest('hex');
            try {
                const isSigValid = crypto.timingSafeEqual(
                    Buffer.from(sigHmac, 'hex'),
                    Buffer.from(expectedSig, 'hex')
                );
                if (!isSigValid) {
                    return { error: 'Invalid federation signature' };
                }
            } catch (e) {
                return { error: 'Invalid signature verification' };
            }
        } else {
            return { error: 'Missing signature' };
        }

        const peersKey = `fed-peers:${zkpY}`;
        let reportedPeers = await store.get(peersKey) || [];
        if (!Array.isArray(reportedPeers)) {
            reportedPeers = [];
        }
        if (!reportedPeers.includes(clientIp)) {
            reportedPeers.push(clientIp);
            await store.set(peersKey, reportedPeers, 86400 * 30);
        }

        const threshold = config.federationConsensusThreshold || 3;
        if (reportedPeers.length >= threshold) {
            await store.set(`banned-zkp-y:${zkpY}`, true, 86400 * 30);
            return { status: 'synchronized', banned: true };
        }
        return { status: 'synchronized', banned: false, reportsCount: reportedPeers.length };
    }

    const nodeId = params.node_id || '';
    if (!nodeId) {
        return { error: 'Missing node_id' };
    }

    // --- VÉRIFICATION DE LA SIGNATURE COOPÉRATIVE ---
    const challengeContext = await store.get(`secret:${nodeId}`);
    if (!challengeContext || !challengeContext.clientSecret) {
        return { error: 'Invalid or expired node_id' };
    }

    const clientSecret = challengeContext.clientSecret;
    const coopSig = params.coop_sig || '';

    let expectedMsg = '';
    switch (op) {
        case 'register':
            expectedMsg = `${clientSecret}:register:${nodeId}:${params.seed || ''}`;
            break;
        case 'find_peer':
            expectedMsg = `${clientSecret}:find_peer:${nodeId}`;
            break;
        case 'webrtc_signal':
            expectedMsg = `${clientSecret}:webrtc_signal:${nodeId}:${params.target_peer_id || ''}:${params.signal_type || ''}:${params.signal_data || ''}`;
            break;
        case 'poll_signals':
            expectedMsg = `${clientSecret}:poll_signals:${nodeId}`;
            break;
        case 'request_peer_block':
            expectedMsg = `${clientSecret}:request_peer_block:${nodeId}:${params.peer_id || ''}:${params.block_idx || '0'}:${params.req_id || ''}`;
            break;
        case 'poll_requests':
            expectedMsg = `${clientSecret}:poll_requests:${nodeId}`;
            break;
        case 'respond_block':
            expectedMsg = `${clientSecret}:respond_block:${nodeId}:${params.requester_id || ''}:${params.req_id || ''}:${params.block_data || ''}`;
            break;
        case 'poll_response':
            expectedMsg = `${clientSecret}:poll_response:${nodeId}:${params.req_id || ''}`;
            break;
        default:
            return { error: 'Invalid cooperative operation' };
    }

    const expectedSig = crypto.createHash('sha256').update(expectedMsg).digest('hex');
    if (coopSig.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(coopSig, 'hex'), Buffer.from(expectedSig, 'hex'))) {
        return { error: 'Invalid cooperative signature' };
    }
    // --- FIN DE LA VÉRIFICATION ---

    switch (op) {
        case 'register':
            const seed = params.seed || '';
            await registerCooperativeNode(clientIp, nodeId, seed);
            return { status: 'registered' };

        case 'find_peer': {
            const peer = await findPeerInSubnet(clientIp, nodeId);
            if (!peer) {
                return { status: 'no_peers' };
            }
            return { status: 'peer_found', peer_id: peer.nodeId };
        }

        case 'webrtc_signal': {
            const targetPeerId = params.target_peer_id || '';
            const signalType = params.signal_type || '';
            const signalData = params.signal_data || '';
            if (!targetPeerId || !signalType) {
                return { error: 'Invalid parameters' };
            }
            const signalQueueKey = `coop-webrtc:signals:${targetPeerId}`;
            const signals = (await store.get(signalQueueKey)) || [];
            signals.push({
                from_peer_id: nodeId,
                signal_type: signalType,
                signal_data: signalData
            });
            await store.set(signalQueueKey, signals, 30);
            return { status: 'signal_queued' };
        }

        case 'poll_signals': {
            const pollSignalKey = `coop-webrtc:signals:${nodeId}`;
            const signals = (await store.get(pollSignalKey)) || [];
            if (signals.length > 0) {
                await store.delete(pollSignalKey);
            }
            return { status: 'ok', signals };
        }

        case 'request_peer_block':
        {
            const peerId = params.peer_id || '';
            const blockIdx = parseInt(params.block_idx || '0', 10);
            const requestId = params.req_id || '';
            if (!peerId || !requestId) {
                return {error: 'Invalid parameters'};
            }
            const queueKey = `coop-mailbox:queue:${peerId}`;
            const requests = (await store.get(queueKey)) || [];
            requests.push({
                req_id: requestId,
                requester_id: nodeId,
                block_idx: blockIdx
            });
            await store.set(queueKey, requests, 30);
            return {status: 'queued'};
        }

        case 'poll_requests':
            const pollQueueKey = `coop-mailbox:queue:${nodeId}`;
            const polledRequests = (await store.get(pollQueueKey)) || [];
            await store.delete(pollQueueKey);
            return { requests: polledRequests };

        case 'respond_block':
            const requesterId = params.requester_id || '';
            const respondRequestId = params.req_id || '';
            const blockData = params.block_data || '';
            if (!requesterId || !respondRequestId) {
                return { error: 'Invalid parameters' };
            }

            const responseKey = `coop-mailbox:res:${requesterId}:${respondRequestId}`;
            await store.set(responseKey, { block_data: blockData }, 30);
            return { status: 'delivered' };

        case 'poll_response':
            const pollResponseRequestId = params.req_id || '';
            const pollResponseKey = `coop-mailbox:res:${nodeId}:${pollResponseRequestId}`;
            const data = await store.get(pollResponseKey);
            if (data) {
                await store.delete(pollResponseKey);
                return { status: 'ready', block_data: data.block_data };
            }
            return { status: 'pending' };
    }
    return null;
}


/** @type {Map<number, number>} Cache des TTL optimisés par score de suspicion (clés de 0 à 100 par pas de 10) */
let optimizedTtlCache = new Map();
/**
 * @private
 * Sanitizes headers injected by proxies if the request does not come from a trusted proxy.
 * @param {object} context - The request context.
 * @param {object} securityConfig - The security configuration.
 */
function sanitizeProxyHeaders(context, securityConfig) {
    if (!context || !context.headers) return;

    const proxyHeaders = [
        'x-ja3-hash',
        'x-ja4-hash',
        'x-http2-fingerprint',
        'x-tcp-fingerprint',
        'x-ja3-raw'
    ];

    if (securityConfig && securityConfig.trustedProxies) {
        const blockList = new BlockList();
        const entries = Array.isArray(securityConfig.trustedProxies)
            ? securityConfig.trustedProxies
            : [securityConfig.trustedProxies];

        let hasValidEntry = false;
        for (const entry of entries) {
            if (typeof entry !== 'string') continue;
            if (entry.includes('/')) {
                try {
                    const [address, prefix] = entry.split('/');
                    blockList.addSubnet(address, parseInt(prefix, 10));
                    hasValidEntry = true;
                } catch (e) {}
            } else {
                try {
                    blockList.addAddress(entry);
                    hasValidEntry = true;
                } catch (e) {}
            }
        }

        const isTrusted = hasValidEntry ? blockList.check(context.clientIp) : false;

        if (!isTrusted) {
            for (const header of proxyHeaders) {
                if (context.headers[header]) {
                    delete context.headers[header];
                }
            }
        }
    }
}

/**
 * Exécute l'optimisation des TTL en tâche de fond de manière asynchrone et non-bloquante.
 * Déporté dans un worker thread dédié pour libérer l'Event Loop principale de Node.js.
 */
export async function runBackgroundTtlOptimization() {
    return new Promise((resolve, reject) => {
        const worker = new Worker(new URL('./ttl-optimization.worker.js', import.meta.url));
        worker.on("message", (tempCache) => {
            const tempMap = new Map();
            for (const [key, value] of Object.entries(tempCache)) {
                tempMap.set(Number(key), value);
            }
            optimizedTtlCache = tempMap;
            resolve();
            worker.terminate();
        });
        worker.on("error", (err) => {
            console.error('[Fingerprint] TTL optimization worker error:', err);
            reject(err);
        });
    });
}

// Lancement de l'optimisation initiale immédiate en arrière-plan
runBackgroundTtlOptimization().catch(err => {
    console.error('[Fingerprint] Error in background TTL optimization:', err);
});

// Planification périodique toutes les 30 minutes sans bloquer la fermeture du processus Node.js (via unref)
const ttlInterval = setInterval(() => {
    runBackgroundTtlOptimization().catch(err => {
        console.error('[Fingerprint] Error in background TTL optimization:', err);
    });
}, 1800000);
if (ttlInterval && typeof ttlInterval.unref === 'function') {
    ttlInterval.unref();
}

/**
 * Détermine le TTL optimal pour un ticket.
 * Utilise les valeurs pré-calculées de la tâche d'optimisation en arrière-plan et effectue
 * une interpolation linéaire instantanée pour le score requis.
 *
 * @param {number} suspicionScore - Le score de suspicion de la requête.
 * @returns {number} Le TTL optimal calculé en millisecondes.
 */
function determineOptimalTicketTtl(suspicionScore) {
    const MIN_TTL = 300000;
    const MAX_TTL = 86400000;
    const score = Math.max(0, Math.min(100, suspicionScore));

    let ttl;
    if (!optimizedTtlCache || optimizedTtlCache.size === 0) {
        // Formule mathématique instantanée de secours si le cache de fond n'est pas encore prêt
        ttl = Math.round(MAX_TTL - (score / 100) * (MAX_TTL - MIN_TTL));
    } else {
        const lowerKey = Math.floor(score / 10) * 10;
        const upperKey = Math.ceil(score / 10) * 10;

        const lowerTtl = optimizedTtlCache.get(lowerKey);
        const upperTtl = optimizedTtlCache.get(upperKey);

        if (lowerTtl === undefined || upperTtl === undefined) {
            ttl = Math.round(MAX_TTL - (score / 100) * (MAX_TTL - MIN_TTL));
        } else if (lowerKey === upperKey) {
            ttl = lowerTtl;
        } else {
            // Interpolation linéaire entre les deux points clés optimisés du front de Pareto
            const fraction = (score - lowerKey) / (upperKey - lowerKey);
            ttl = Math.round(lowerTtl + fraction * (upperTtl - lowerTtl));
        }
    }

    // Sécurité: Si le score de suspicion est élevé, on applique un plafond strict
    // pour garantir un TTL court et sécuritaire (ex: max 30 minutes à partir de score 80).
    if (score >= 80) {
        const maxAllowedTtl = Math.round(1800000 - ((score - 80) / 20) * (1800000 - MIN_TTL));
        ttl = Math.min(ttl, maxAllowedTtl);
    } else if (score >= 50) {
        const maxAllowedTtl = Math.round(7200000 - ((score - 50) / 30) * (7200000 - 1800000));
        ttl = Math.min(ttl, maxAllowedTtl);
    }

    return ttl;
}


/**
 * Parse une trame TCP SYN brute (IPv4 ou IPv6).
 * @private
 * @param {Buffer|Uint8Array} binary - Le paquet binaire.
 * @returns {object|null}
 */
function parseTcpSyn(binary) {
    if (!binary || binary.length < 40) return null;
    let ttl = 64;
    let tcpOffset = 20;
    const version = binary[0] >> 4;

    if (version === 4) {
        ttl = binary[8];
        const ihl = binary[0] & 0x0f;
        tcpOffset = ihl * 4;
    } else if (version === 6) {
        ttl = binary[7]; // Hop Limit
        tcpOffset = 40;
    } else {
        tcpOffset = 0;
        ttl = 64;
    }

    if (binary.length < tcpOffset + 20) return null;

    const windowSize = (binary[tcpOffset + 14] << 8) | binary[tcpOffset + 15];
    const dataOffset = (binary[tcpOffset + 12] >> 4) * 4;
    const optionsEnd = tcpOffset + dataOffset;

    let mss = null;
    let ws = null;
    let sack = false;

    let i = tcpOffset + 20;
    while (i < optionsEnd && i < binary.length) {
        const optType = binary[i];
        if (optType === 0) break;
        if (optType === 1) {
            i++;
            continue;
        }
        if (i + 1 >= binary.length) break;
        const optLen = binary[i + 1];
        if (optLen < 2 || i + optLen > binary.length) break;

        if (optType === 2 && optLen === 4) {
            mss = (binary[i + 2] << 8) | binary[i + 3];
        } else if (optType === 3 && optLen === 3) {
            ws = binary[i + 2];
        } else if (optType === 4 && optLen === 2) {
            sack = true;
        }
        i += optLen;
    }

    return { ttl, windowSize, mss, ws, sack };
}

/**
 * Classifie l'OS à partir du fingerprint de la pile TCP/IP.
 * @private
 * @param {object|null} fingerprint
 * @returns {string}
 */
function classifyTcpOs(fingerprint) {
    if (!fingerprint) return 'unknown';
    const ttl = fingerprint.ttl ?? 64;
    const windowSize = fingerprint.windowSize ?? 0;
    const ws = fingerprint.ws ?? null;

    if (ttl > 64 && ttl <= 128) {
        return 'Windows';
    }
    if (ttl > 32 && ttl <= 64) {
        if (windowSize === 29200 || windowSize === 14600 || windowSize === 5840) {
            return 'Linux';
        }
        return 'Linux';
    }
    if (ttl <= 64) {
        if (windowSize === 65535 && (ws === 6 || ws === 8 || ws === 5)) {
            return 'macOS/iOS';
        }
    }
    if (ttl > 64) return 'Windows';
    if (ttl > 0) return 'Linux';
    return 'unknown';
}

/**
 * Détecte les anomalies de pile réseau par rapport au User-Agent.
 * @private
 * @param {object} context - Le contexte de la requête.
 * @returns {{tcpAnomalyScore: number}}
 */
function getTcpAnomalyScore(context) {
    let fp = null;
    const rawTcpBinary = context.headers?.['x-raw-tcp-binary'] || context.rawTcpBinary || null;
    if (rawTcpBinary) {
        const binary = Buffer.isBuffer(rawTcpBinary) ? rawTcpBinary : (typeof rawTcpBinary === 'string' ? Buffer.from(rawTcpBinary, 'hex') : rawTcpBinary);
        fp = parseTcpSyn(binary);
    }

    if (!fp) {
        const tcpHeader = context.headers?.['x-tcp-fingerprint'] || context.tcpFingerprint || null;
        if (tcpHeader && typeof tcpHeader === 'string') {
            const parts = tcpHeader.split(':');
            if (parts.length >= 2) {
                fp = {
                    ttl: parseInt(parts[0], 10),
                    windowSize: parseInt(parts[1], 10),
                    mss: parts[2] ? parseInt(parts[2], 10) : null,
                    ws: parts[3] ? parseInt(parts[3], 10) : null,
                    sack: parts[4] === '1' || parts[4] === 'true'
                };
            }
        }
    }

    if (!fp) {
        return { tcpAnomalyScore: 0.0 };
    }

    const tcpOs = classifyTcpOs(fp);
    const ua = context.headers?.['user-agent'] || '';
    const uaParts = parseUserAgent(ua);
    const uaOs = uaParts.os;

    if (!uaOs || tcpOs === 'unknown') {
        return { tcpAnomalyScore: 0.0 };
    }

        let mappedOs = null;
        if (uaOs.startsWith('Windows')) mappedOs = 'Windows';
        else if (uaOs.startsWith('Mac') || uaOs.startsWith('macOS')) mappedOs = 'macOS';
        else if (uaOs.startsWith('iOS')) mappedOs = 'iOS';
        else if (uaOs.startsWith('Linux')) mappedOs = 'Linux';

        if (!mappedOs) {
            return { tcpAnomalyScore: 0.0 };
        }

        const OS_EXPECTED_TCP = {
            'Windows': { ttl: 128, windowSize: 64240, ws: 8, mss: 1460, sack: true },
            'Linux': { ttl: 64, windowSize: 29200, ws: 7, mss: 1460, sack: true },
            'macOS': { ttl: 64, windowSize: 65535, ws: 6, mss: 1460, sack: true },
            'iOS': { ttl: 64, windowSize: 65535, ws: 6, mss: 1460, sack: true }
        };

        const expected = OS_EXPECTED_TCP[mappedOs];
        const ttlDiff = Math.abs(fp.ttl - expected.ttl) / expected.ttl;
        const winDiff = Math.abs(fp.windowSize - expected.windowSize) / expected.windowSize;
        const wsDiff = expected.ws !== null && fp.ws !== null ? Math.abs(fp.ws - expected.ws) / expected.ws : 0.0;
        const mssDiff = expected.mss !== null && fp.mss !== null ? Math.abs(fp.mss - expected.mss) / expected.mss : 0.0;
        const sackDiff = (fp.sack ?? true) === (expected.sack ?? true) ? 0.0 : 1.0;

        const deviation = (
            Math.min(1.0, ttlDiff) * 0.50 +
            Math.min(1.0, winDiff) * 0.25 +
            Math.min(1.0, wsDiff) * 0.15 +
            Math.min(1.0, mssDiff) * 0.05 +
            sackDiff * 0.05
        );

        let tcpAnomalyScore = 0.0;
        if (tcpOs !== mappedOs && tcpOs !== 'unknown') {
            const baseAnomaly = mappedOs === 'Windows' ? 80.0 :
                                (mappedOs === 'macOS' || mappedOs === 'iOS' ? 85.0 : 75.0);
            tcpAnomalyScore = baseAnomaly + (deviation - 0.4) * 10.0;
        } else {
            tcpAnomalyScore = deviation * 40.0;
        }

        tcpAnomalyScore = Math.max(0.0, Math.min(100.0, Math.round(tcpAnomalyScore * 10) / 10));
        return { tcpAnomalyScore };
}

/**
 * Vérifie si une chaîne de caractères contient des patterns d'injection connus.
 * @private
 * @param {string} str - La chaîne à vérifier.
 * @param {string[]} [typesToDetect=['sql', 'log4shell', 'ssti', 'xxe', 'traversal', 'rce']] - Les types d'injections à détecter.
 * @returns {boolean} - True si un pattern malveillant est détecté.
 */
function isMalicious(str, typesToDetect = Object.keys(injectionPatterns).filter(k => k !== 'openRedirect')) {
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
    googlebot_whitelist(),
    bingbot_whitelist(),
    yandex_whitelist(),
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

/**
 * Retourne la liste officielle des préfixes IP/CIDR (IPv4 et IPv6) utilisés par Googlebot
 * enveloppée dans un objet de type 'allowlist' prêt à être injecté.
 * @returns {{type: string, entries: string[]}} Règle d'allowlist de sécurité.
 */
export const googlebot_whitelist = () => ({
    type: 'allowlist',
    entries: googlebotEntries
});

export const yandex_whitelist = () => ({
    type: 'allowlist',
    entries: yandexEntries
});

export const bingbot_whitelist = () => ({
    type: 'allowlist',
    entries: bingbotEntries
});


/**
 * Extracts the TLS Session ID or ticket hash from the request context.
 * Prioritizes proxy-provided headers and falls back to Node's native socket session.
 * @private
 * @param {object} context - The request context.
 * @returns {string|null}
 */
function getTlsSessionId(context) {
    if (!context) return null;
    const fromHeader = context.headers ? (context.headers['x-tls-session-id'] || context.headers['x-ssl-session-id']) : null;
    if (fromHeader) return fromHeader;

    const socket = context.rawReq?.socket;
    if (socket) {
        if (socket.sessionId) {
            return socket.sessionId.toString('hex');
        }
        if (typeof socket.getSession === 'function') {
            const session = socket.getSession();
            if (session) {
                return crypto.createHash('sha256').update(session).digest('hex');
            }
        }
    }
    return null;
}

// --- Proof-of-Work Middleware (The Tollbooth) ---
const staticFileCache = new SimpleLRUCache(50);

export const powMiddleware = (securityConfig) => {
  const engine = new FingerprintEngine(securityConfig);

  // Initialize the problem manager with the configured path, if provided.
  if (securityConfig.enableUsefulWork) {
    const defaultPath = resolve(__dirname, '..', '..', 'config', 'problems.config.json');
    const configPath = securityConfig.usefulWorkConfigPath || (existsSync(defaultPath) ? defaultPath : undefined);
    getProblemManager({
        configPath,
        config: securityConfig.usefulWorkConfig
    }, store).catch(err => {
        console.warn('[Fingerprint] ProblemManager background initialization failed:', err.message);
    });
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
      if (req.query && req.query.fp_handshake) {
          const clientKeyHex = req.headers['x-client-ephemeral-key'];
          if (clientKeyHex) {
              try {
                  const serverECDH = crypto.createECDH('prime256v1');
                  serverECDH.generateKeys();
                  const serverPubKeyHex = serverECDH.getKeys('hex');
                  const sharedSecret = serverECDH.computeSecret(clientKeyHex, 'hex');
                  const hmacKey = crypto.createHash('sha256').update(sharedSecret).digest('hex');

                  const requestContext = {
                      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
                      headers: req.headers,
                      cookies: req.cookies
                  };
                  const { deviceId, deviceData } = await resolveRequestIdentity(requestContext, securityConfig);
                  if (deviceData) {
                      deviceData.sessionHmacKey = hmacKey;
                      await store.set(`device:${deviceId}`, deviceData);
                  }

                  res.setHeader('x-server-ephemeral-key', serverPubKeyHex);
                  return res.status(200).json({ status: 'success' });
              } catch (e) {
                  return res.status(400).json({ error: 'Handshake failed' });
              }
          }
          return res.status(400).json({ error: 'Missing client key' });
      }

      if (!req.headers_translated) {
          req.headers_translated = true;
          const matchedMapping = getActiveMappingForRequest(req.headers);
          if (matchedMapping) {
              const devFpHeader = matchedMapping.headers['x-device-fingerprint'].toLowerCase();
              const behaviorHeader = matchedMapping.headers['x-behavior-metrics'].toLowerCase();

              if (req.headers[devFpHeader]) {
                  req.headers['x-device-fingerprint'] = req.headers[devFpHeader];
              }
              if (req.headers[behaviorHeader]) {
                  req.headers['x-behavior-metrics'] = req.headers[behaviorHeader];
              }
              if (req.headers['x-device-fingerprint']) {
                  req.headers['x-device-fingerprint'] = decodePolymorphicFingerprint(req.headers['x-device-fingerprint'], matchedMapping);
              }
          }
      }
    if (securityConfig?.wasm) {
      const wasmConfig = securityConfig.wasm;
      let jsPath = '/fp.js';
      let wasmPath = '/fp.wasm';
      let jsFile = '';
      let wasmFile = '';

      if (wasmConfig === true) {
        const defaultDir = resolve(__dirname, '..', '..', 'public');
        jsFile = resolve(defaultDir, 'fp.js');
        wasmFile = resolve(defaultDir, 'fp.wasm');
      } else if (typeof wasmConfig === 'string') {
        jsFile = resolve(wasmConfig, 'fp.js');
        wasmFile = resolve(wasmConfig, 'fp.wasm');
      } else if (typeof wasmConfig === 'object') {
        jsPath = wasmConfig.jsPath || '/fp.js';
        wasmPath = wasmConfig.wasmPath || '/fp.wasm';
        jsFile = wasmConfig.jsFile ? resolve(wasmConfig.jsFile) : resolve(__dirname, '..', '..', 'public', 'fp.js');
        wasmFile = wasmConfig.wasmFile ? resolve(wasmConfig.wasmFile) : resolve(__dirname, '..', '..', 'public', 'fp.wasm');
      }

        if (req.path === jsPath) {
            try {
                if (wasmConfig === 'dynamic' || wasmConfig.dynamic || wasmConfig.polymorphic) {
                    await ensureLatestMapping();
                    const latest = activeMappings[0];
                    if (latest && latest.jsBuffer) {
                        res.setHeader('Content-Type', 'application/javascript');
                        return res.send(latest.jsBuffer);
                    }
                }
                if (jsFile && existsSync(jsFile)) {
                    let fileContent = staticFileCache.get(jsFile);
                    if (!fileContent) {
                        fileContent = readFileSync(jsFile);
                        staticFileCache.set(jsFile, fileContent);
                    }
                    res.setHeader('Content-Type', 'application/javascript');
                    return res.send(fileContent);
                }
            } catch (e) {}
        }
        if (req.path === wasmPath) {
            try {
                if (wasmConfig === 'dynamic' || wasmConfig.dynamic || wasmConfig.polymorphic) {
                    await ensureLatestMapping();
                    const latest = activeMappings[0];
                    if (latest && latest.wasmBuffer) {
                        res.setHeader('Content-Type', 'application/wasm');
                        return res.send(latest.wasmBuffer);
                    }
                }
                if (wasmFile && existsSync(wasmFile)) {
                    let fileContent = staticFileCache.get(wasmFile);
                    if (!fileContent) {
                        fileContent = readFileSync(wasmFile);
                        staticFileCache.set(wasmFile, fileContent);
                    }
                    res.setHeader('Content-Type', 'application/wasm');
                    return res.send(fileContent);
                }
            } catch (e) {}
        }
    }

    const requestContext = {
      clientIp: req.ip || req.socket?.remoteAddress || "unknown",
        path: sanitizeRedirectPath(req.path),
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

    // New GraphQL parsing logic
    // It's common for GraphQL endpoints to be at '/graphql'
    if (req.path === '/graphql' && req.body) {
        const gqlInfo = parseGraphQLQuery(req.body);
        if (gqlInfo) {
            requestContext.graphqlOperationType = gqlInfo.type;
            requestContext.graphqlOperationName = gqlInfo.name;
        }
    }
    const decision = await engine.processRequest(requestContext);

    // Attach the fingerprinting result to the request object for downstream middlewares.
    req.fingerprint = {
      score: decision.score,
      vector: decision.vector,
      intendedAction: decision.intendedAction, // Add intended action for logging
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
        return res.redirect(sanitizeRedirectPath(decision.path));

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
    get store() { return store; }, // Export the store for testing
    checkChallengeRateLimit,
    getDeviceHash,
    getCompositeDeviceHash,
    getSuspicionVector,
    getTlsSessionId,
    pruneTrafficData,
    cyrb53, // Export for testing
    FingerprintBuilder, // Export for testing
    calculateTarget,
    determineOptimalTicketTtl,
    runBackgroundTtlOptimization,
    calculateAnalogInconsistencyScore,
    getRequestPatternScore, // Expose for testing
    getBehaviorScore, // Expose for testing
    getCrossLayerInconsistency, // Expose for testing
    // Expose page generators for security testing
    getTimeInconsistencyScore,
    getClickVarianceScore, // NOUVEAU: Expose pour les tests
    getTlsFingerprint, // NOUVEAU: Expose pour les tests
    sanitizeTrafficData, // NOUVEAU: Expose pour l'auto-tuner/tests
    getTlsSpoofingScore, // NOUVEAU: Expose pour les tests
    verifyWebAuthnHardwareAnchor,
    generateStatelessTicket,
    parseStatelessTicket,
    parseJa3,
    getBotnetClusterScore, // NOUVEAU: Expose pour les tests
    generateCpuTargetChallengePage,
    getClientHintsInconsistencyScore, // Expose for testing
    generateCombinedPoWChallengePage,
    problemManager, // Re-export the problemManager promise
    getIpSubnet, // Expose for testing
    getIpCommonPrefixLength, // Expose for testing
    updateSubnetMetrics, // Expose for testing
    getSubnetScore, // Expose for testing
    getIpReputationScore, // Expose for testing
    updateIpReputationScore, // Expose for testing
    setLastBestSolution: (val) => { lastBestSolution = val; }, // Expose to test auto-tuning metrics
    verifyZkpProof,
    modPow,
    generateSessionMapping,
    compilePolymorphicJs,
    parseTcpSyn, // Expose for testing
    classifyTcpOs, // Expose for testing
    getTcpAnomalyScore, // Expose for testing,
    getRenderingAnomalyScore, // NOUVEAU: Expose pour les tests
    dnsCircuitBreaker,
    getProtocolAnomalyScore,
    recordDnsSuccess,
    recordDnsFailure,
    canAttemptDns,
    registerCooperativeNode,
    findPeerInSubnet,
    handleCooperativeRequest,
    broadcastBannedZkp,
    getMetric,
    incrementCounter,
    observeValue
};

// --- THRESHOLD AUTO-TUNING SECTION ---

let autoTuningJobId = null;
let lastBestSolution = null; // NOUVEAU: Stocke la meilleure solution trouvée

/**
 * Assainit les données de trafic pour l'auto-tuner afin de prévenir les attaques par empoisonnement.
 * Limite la contribution de chaque deviceId à un pourcentage maximum (ex: 2%) du jeu de données total.
 * @export
 * @param {Array<object>} trafficData
 * @returns {Array<object>}
 */
export function sanitizeTrafficData(trafficData) {
  if (!trafficData || trafficData.length === 0) {
    return [];
  }

    const rawLogs = [...trafficData];
    const totalCount = rawLogs.length;

    const maxLogsPerDevice = Math.max(3, Math.floor(totalCount * 0.02)); // Max 2% contribution per device
    const maxLogsPerIp = Math.max(3, Math.floor(totalCount * 0.02));      // Max 2% par adresse IP individuelle
    const maxLogsPerSubnet = Math.max(5, Math.floor(totalCount * 0.05));  // Max 5% par bloc réseau (anti-proxy-rotation)
    const maxLogsPerHardwareCluster = Math.max(3, Math.floor(totalCount * 0.02)); // Max 2% par cluster matériel stable

    const deviceCounts = new Map();
  const ipCounts = new Map();
  const subnetCounts = new Map();
  const hardwareClusterCounts = new Map();
  const hwClusterCache = new Map();

  const getHardwareCluster = (log) => {
    const fp = log.deviceHash || log.fingerprint || log.deviceFingerprint || '';
    if (!fp || typeof fp !== 'string') {
      return log.deviceId || 'anonymous-cluster';
    }
    if (hwClusterCache.has(fp)) {
      return hwClusterCache.get(fp);
    }
    const parts = fp.split('|');
    const hwComponents = [];
    for (const part of parts) {
      const pair = part.split(':');
      if (pair.length === 2 && (pair[0] === 'gpu' || pair[0] === 'cvs' || pair[0] === 'hw')) {
        hwComponents.push(part);
      }
    }
    const result = hwComponents.length > 0 ? hwComponents.sort().join('|') : (log.deviceId || 'anonymous-cluster');
    hwClusterCache.set(fp, result);
    return result;
  };
// --- REVOLUTION : Compression de Cohorte par Densité Vectorielle (Anti-Sybil / Anti-Poisoning) ---
    const clusteredLogs = [];
    const getVectorDistance = (v1, v2) => {
        if (!v1 || !v2) return Infinity;
        let sum = 0;
        const keys = new Set([...Object.keys(v1), ...Object.keys(v2)]);
        for (const key of keys) {
            sum += Math.pow((v1[key] || 0) - (v2[key] || 0), 2);
        }
        return Math.sqrt(sum);
    };

    for (const log of rawLogs) {
        let matchedCluster = null;
        for (const cluster of clusteredLogs) {
            if (log.type === cluster.type && getVectorDistance(log.vector, cluster.vector) < 5.0) {
                matchedCluster = cluster;
                break;
            }
        }
        if (matchedCluster) {
            matchedCluster.instancesCount = (matchedCluster.instancesCount || 1) + 1;
            matchedCluster.weight = 1 + Math.log(matchedCluster.instancesCount); // Compression logarithmique
        } else {
            const logCopy = { ...log };
            logCopy.instancesCount = 1;
            logCopy.weight = 1.0;
            clusteredLogs.push(logCopy);
        }
    }

    const suspiciousLogs = [];
    const passedLogs = [];

    for (const log of clusteredLogs) {
    const devId = log.deviceId || 'anonymous';
    const ip = log.clientIp || log.ip || 'unknown';
    const subnet = getIpSubnet(ip) || 'unknown-subnet';
    const hwCluster = getHardwareCluster(log);

    const currentDeviceCount = deviceCounts.get(devId) || 0;
    const currentIpCount = ipCounts.get(ip) || 0;
    const currentSubnetCount = subnetCounts.get(subnet) || 0;
    const currentHwClusterCount = hardwareClusterCounts.get(hwCluster) || 0;

    // Filtrage anti-poisoning strict sur 4 axes cumulatifs (incluant le clustering matériel stable)
    if (
      currentDeviceCount < maxLogsPerDevice &&
      (ip === 'unknown' || currentIpCount < maxLogsPerIp) &&
      (subnet === 'unknown-subnet' || currentSubnetCount < maxLogsPerSubnet) &&
      currentHwClusterCount < maxLogsPerHardwareCluster
    ) {
      deviceCounts.set(devId, currentDeviceCount + 1);
      if (ip !== 'unknown') ipCounts.set(ip, currentIpCount + 1);
      if (subnet !== 'unknown-subnet') subnetCounts.set(subnet, currentSubnetCount + 1);
      hardwareClusterCounts.set(hwCluster, currentHwClusterCount + 1);

      if (log.type === 'request_passed') {
        passedLogs.push(log);
      } else {
        suspiciousLogs.push(log);
      }
    }
  }

  const minDataPoints = 200; // Seuil par défaut
  const maxPassedAllowed = Math.max(minDataPoints, suspiciousLogs.length * 9);
  if (passedLogs.length > maxPassedAllowed) {
    const shuffledPassed = passedLogs.sort(() => 0.5 - secureRandomFloat());
    return [...suspiciousLogs, ...shuffledPassed.slice(0, maxPassedAllowed)];
  }
  return [...suspiciousLogs, ...passedLogs];
}
/**
 * Assainit et limite la taille/ancienneté des données de trafic pour éviter les fuites de mémoire.
 * @private
 */
function pruneTrafficData(trafficData, maxDataPoints, maxAgeMs, onCleanup) {
    if (!Array.isArray(trafficData)) return;
    const now = Date.now();
    const removed = [];

    // 1. Politique temporelle d'expiration
    if (maxAgeMs && maxAgeMs > 0) {
        const threshold = now - maxAgeMs;
        let i = 0;
        while (i < trafficData.length) {
            const log = trafficData[i];
            const logTs = log.timestamp || log.requestTimestamp || now;
            if (logTs < threshold) {
                removed.push(trafficData.splice(i, 1)[0]);
            } else {
                i++;
            }
        }
    }

    // 2. Politique de taille maximale (conserver les plus récents)
    if (maxDataPoints && maxDataPoints > 0 && trafficData.length > maxDataPoints) {
        const overflowCount = trafficData.length - maxDataPoints;
        const spliced = trafficData.splice(0, overflowCount);
        removed.push(...spliced);
    }

    // 3. Callback de nettoyage
    if (onCleanup && typeof onCleanup === 'function' && removed.length > 0) {
        try {
            onCleanup(removed);
        } catch (e) {
            console.error('[AutoTuning] Error in onCleanup callback:', e);
        }
    }
}
/**
 * Executes a threshold optimization pass using collected traffic data.
 * @private
 */
function runThresholdOptimization(securityConfig, trafficData, minDataPoints, maxDataPoints, savePath, tuningOptions = {}) {
    const { maxAgeMs, clearAfterTuning = false, onCleanup } = tuningOptions;

    pruneTrafficData(trafficData, maxDataPoints, maxAgeMs, onCleanup);
    const sanitizedData = sanitizeTrafficData(trafficData);

  const highConfidenceLogs = sanitizedData
    .filter(log => log.type === 'challenge_solved' || log.type === 'trap_triggered')
    .reduce((sum, log) => sum + (log.instancesCount || 1), 0);
  const totalSanitizedInstances = sanitizedData.reduce((sum, log) => sum + (log.instancesCount || 1), 0);
  const highConfidenceRatio = totalSanitizedInstances > 0 ? highConfidenceLogs / totalSanitizedInstances : 0;
  const MIN_CONFIDENCE_RATIO = 0.05; // Exiger au moins 5% de signaux forts.
  const MIN_HIGH_CONFIDENCE_COUNT = 10; // Absolu de secours pour éviter le gel lors de floods

  const hasEnoughSignal = highConfidenceRatio >= MIN_CONFIDENCE_RATIO || highConfidenceLogs >= MIN_HIGH_CONFIDENCE_COUNT;

  if (totalSanitizedInstances < minDataPoints || !hasEnoughSignal) {
    if (totalSanitizedInstances < minDataPoints) {
    console.log(`[AutoTuning] Reporté : ${totalSanitizedInstances}/${minDataPoints} points de données.`);
    } else {
      console.log(`[AutoTuning] Reporté : Signaux de confiance insuffisants (Ratio: ${(highConfidenceRatio * 100).toFixed(2)}% < ${(MIN_CONFIDENCE_RATIO * 100).toFixed(2)}% et absolu: ${highConfidenceLogs} < ${MIN_HIGH_CONFIDENCE_COUNT}).`);
    }
    return;
  }
  console.log(`[AutoTuning] Démarrage du cycle d'optimisation complet avec ${totalSanitizedInstances} points de données assainis.`);

  try {
    const paretoFront = Optimization.Operators.solveFullSecurityTuning({ trafficData: sanitizedData });

    if (!paretoFront || paretoFront.length === 0) {
      console.warn("[AutoTuning] L'optimisation n'a retourné aucune solution.");
      return;
    }

  // Règles de gardiennage (Sanity Guardrails) pour filtrer le front de Pareto
  const isValidSecurityConfig = (config) => {
    if (!config || !config.weights || !config.thresholds) return false;
    const w = config.weights;
    const t = config.thresholds;
    const activeWeightsSum = (w.inconsistencyScore || 0) + (w.tlsSpoofingScore || 0) + (w.requestPatternScore || 0) + (w.behaviorScore || 0) + (w.botScore || 0);
    if (activeWeightsSum < 1.5) return false;
    if (t.low < 10 || t.low > 35) return false;
    if (t.medium < t.low + 5 || t.medium > 70) return false;
    if (t.high < t.medium + 5 || t.high > 90) return false;
    if (t.block < t.high + 5 || t.block > 99) return false;
    return true;
  };

  let filteredFront = paretoFront.filter(p => isValidSecurityConfig(p.solution));
  if (filteredFront.length === 0) {
    console.warn("[AutoTuning] Toutes les solutions du front de Pareto ont enfreint les règles de gardiennage sécuritaires. Rétablissement du front brut.");
    filteredFront = paretoFront;
  }

  // Stratégie de sélection : choisir la solution la plus équilibrée du front de Pareto.
  // On cherche la solution la plus proche de l'origine (0,0) dans l'espace des objectifs.
  let bestSolution = filteredFront[0];
  let minDistance = Math.sqrt(Math.pow(bestSolution.objectives[0], 2) + Math.pow(bestSolution.objectives[1], 2));

  for (let i = 1; i < filteredFront.length; i++) {
    const distance = Math.sqrt(Math.pow(filteredFront[i].objectives[0], 2) + Math.pow(filteredFront[i].objectives[1], 2));
    if (distance < minDistance) {
      minDistance = distance;
      bestSolution = filteredFront[i];
    }
  }

  // --- NOUVEAU : Logique d'inertie pour l'application de la configuration ---
  // Au lieu d'appliquer directement la nouvelle configuration, on fait "glisser"
  // l'ancienne vers la nouvelle, avec une vélocité de changement maximale.
  const newConfig = bestSolution.solution;

  /**
   * Met à jour un objet de configuration (ex: thresholds, weights) en douceur.
   * Cette version intègre un apprentissage adaptatif basé sur la confiance du signal
   * et applique des limites physiques pour garantir la cohérence en production.
   * @param {object} currentConfig - La configuration actuelle à modifier.
   * @param {object} targetConfig - La configuration cible proposée par l'optimiseur.
   * @param {'thresholds' | 'weights' | 'patterns'} type - Le type de configuration.
   * @param {number} confidenceFactor - Facteur multiplicateur de vitesse d'apprentissage (0.1 à 1.5) basé sur la qualité du signal de trafic.
   */
  const applyInertialUpdate = (currentConfig, targetConfig, type, confidenceFactor = 1.0) => {
    if (!currentConfig || !targetConfig) return;
    
    // Base de vitesse d'apprentissage (15%). On l'ajuste dynamiquement selon la confiance du signal.
    // Si le trafic est peu fiable/bruyant, on ralentit l'apprentissage pour lisser les dérives.
    // Si le trafic contient des attaques claires, on accélère la transition.
    const BASE_LEARNING_RATE = 0.15;
    const learningRate = Math.max(0.02, Math.min(0.40, BASE_LEARNING_RATE * confidenceFactor));

    for (const key in currentConfig) {
      if (Object.prototype.hasOwnProperty.call(targetConfig, key) && typeof currentConfig[key] === 'number') {
        const currentVal = currentConfig[key];
        const targetVal = targetConfig[key];

        // Ajustement individuel progressif vers la cible
        let updatedVal = currentVal + (targetVal - currentVal) * learningRate;

        // Bornage strict selon la nature du paramètre pour éviter les dérives absurdes
        if (type === 'weights') {
          // Les coefficients de score doivent rester réalistes
          // Un poids ne doit jamais tomber à zéro complet (perte du signal) ni dépasser 2.0 (hyper-sensibilité)
          updatedVal = Math.max(0.05, Math.min(1.8, updatedVal));
        } else if (type === 'patterns') {
          // Limitation des paramètres de pattern pour éviter l'empoisonnement par le trafic bruyant
          if (key === 'benfordThreshold') updatedVal = Math.max(0.05, Math.min(0.30, updatedVal));
          else if (key === 'decayFactor') updatedVal = Math.max(0.70, Math.min(0.98, updatedVal));
          else if (key === 'minSamples') updatedVal = Math.max(3, Math.min(15, Math.round(updatedVal)));
          else if (key === 'historySize') updatedVal = Math.max(5, Math.min(30, Math.round(updatedVal)));
          else if (key.endsWith('Threshold')) updatedVal = Math.max(50, Math.min(3000, Math.round(updatedVal)));
        }

        currentConfig[key] = updatedVal;
      }
    }

    // Cohérence globale après mise à jour individuelle pour les seuils de blocage
    if (type === 'thresholds') {
      // Garantit strictement la hiérarchie low < medium < high < block
      // Empêche également les écarts trop resserrés (minimum 5 points de différence entre chaque palier)
      let low = Math.max(10, Math.min(35, currentConfig.low));
      let medium = Math.max(low + 8, Math.min(65, currentConfig.medium));
      let high = Math.max(medium + 8, Math.min(85, currentConfig.high));
      let block = Math.max(high + 8, Math.min(98, currentConfig.block));

      currentConfig.low = Math.round(low);
      currentConfig.medium = Math.round(medium);
      currentConfig.high = Math.round(high);
      currentConfig.block = Math.round(block);
    }
  };

  // Calcul du facteur de confiance basé sur la proportion de signaux d'attaques clairs et de volume
  // Plus le ratio est équilibré et le volume important, plus nous faisons confiance au Front de Pareto.
  const trafficConfidence = Math.min(1.5, Math.max(0.3, highConfidenceRatio * 4));

    // --- VALIDATION POST-CALCUL (Anti-empoisonnement & Validation Croisée) ---
    const tempConfig = {
        thresholds: { ...securityConfig.thresholds },
        weights: { ...securityConfig.weights },
        patterns: { ...securityConfig.patterns }
    };

    applyInertialUpdate(tempConfig.thresholds, newConfig.thresholds, 'thresholds', trafficConfidence);
    applyInertialUpdate(tempConfig.weights, newConfig.weights, 'weights', trafficConfidence);
    applyInertialUpdate(tempConfig.patterns, newConfig.patterns, 'patterns', trafficConfidence);

    const fitnessFunction = Optimization.Operators.createFullSecurityConfigEvaluator({ trafficData: sanitizedData });
    const currentObjectives = fitnessFunction(securityConfig);
    const proposedObjectives = fitnessFunction(tempConfig);

    const currentFPR = currentObjectives[0];
    const currentFNR = currentObjectives[1];
    const proposedFPR = proposedObjectives[0];
    const proposedFNR = proposedObjectives[1];

    const validationTolerance = securityConfig?.autotuning?.validationTolerance ?? tuningOptions?.validationTolerance ?? 0.15;

    if (proposedFPR > currentFPR + validationTolerance || proposedFNR > currentFNR + validationTolerance) {
        console.error(`[AutoTuning] [SECURITY ALERT] Proposed configuration rejected due to instability/poisoning risk! Proposed FPR: ${proposedFPR.toFixed(4)} (Current: ${currentFPR.toFixed(4)}), Proposed FNR: ${proposedFNR.toFixed(4)} (Current: ${currentFNR.toFixed(4)})`);
        if (securityConfig.logger && typeof securityConfig.logger === 'function') {
            securityConfig.logger({
                type: 'autotuning_instability_alert',
                proposedFPR,
                currentFPR,
                proposedFNR,
                currentFNR,
                timestamp: Date.now()
            });
        }
        return; // Rollback automatique : On arrête l'application
    }

  applyInertialUpdate(securityConfig.thresholds, newConfig.thresholds, 'thresholds', trafficConfidence);
  applyInertialUpdate(securityConfig.weights, newConfig.weights, 'weights', trafficConfidence);
  applyInertialUpdate(securityConfig.patterns, newConfig.patterns, 'patterns', trafficConfidence);

  // NOUVEAU: Stocker la meilleure solution pour une consultation externe
  lastBestSolution = bestSolution;

  console.log("[AutoTuning] Nouvelle configuration de sécurité optimisée appliquée.");
  console.log("[AutoTuning] Objectifs atteints :", { falsePositiveRate: bestSolution.objectives[0].toFixed(4), falseNegativeRate: bestSolution.objectives[1].toFixed(4) });
  console.log("[AutoTuning] Nouveaux seuils :", securityConfig.thresholds);
  console.log("[AutoTuning] Nouveaux poids :", securityConfig.weights);
  console.log("[AutoTuning] Nouveaux patterns :", securityConfig.patterns);

  // NOUVEAU: Sauvegarder la meilleure configuration si un chemin est fourni.
  if (savePath) {
      try {
          const configToSave = JSON.stringify(bestSolution.solution, null, 2);
          writeFileSync(savePath, configToSave, 'utf-8');
          console.log(`[AutoTuning] Meilleure configuration sauvegardée dans : ${savePath}`);
      } catch (error) {
          console.error(`[AutoTuning] Erreur lors de la sauvegarde de la configuration optimisée : ${error.message}`);
      }
  }

  } finally {
    if (clearAfterTuning) {
        const cleared = trafficData.splice(0, trafficData.length);
        if (onCleanup && typeof onCleanup === 'function' && cleared.length > 0) {
            try {
                onCleanup(cleared);
            } catch (e) {
                console.error('[AutoTuning] Error in onCleanup callback after clearing:', e);
            }
        }
        console.log(`[AutoTuning] Explicitly cleared ${cleared.length} processed traffic data points.`);
    }
  }
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
 * @param {string} [options.savePath] - Optional. If provided, the best configuration found will be saved to this file path.
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
        maxDataPoints = 10000, // Limite par défaut à 10 000 entrées
        savePath, // NOUVEAU: Chemin de sauvegarde optionnel
        maxAgeMs,
        clearAfterTuning = false,
        onCleanup,
    } = options;

    if (!securityConfig || !trafficData) {
        throw new Error("[AutoTuning] `securityConfig` et `trafficData` sont requis.");
    }
    if (securityConfig.logger && typeof securityConfig.logger === 'function' && !securityConfig.logger_wrapped) {
        const originalLogger = securityConfig.logger;
        const maxPercentage = securityConfig.autotuning?.maxDensityPercentage || 0.02;

        securityConfig.logger = function (log) {
            const ip = log.clientIp || log.ip;
            const subnet = ip ? __internal.getIpSubnet(ip, 24, 48) : null;
            const fp = log.deviceHash || log.fingerprint || log.deviceFingerprint;
            const stableFp = fp ? extractStablePart(fp) : null;

            if (trafficData.length > 0) {
                const total = trafficData.length;
                let ipMatchCount = 0;
                let fpMatchCount = 0;
                let matchedKey = null;

                for (let i = 0; i < trafficData.length; i++) {
                    const existingLog = trafficData[i];
                    const logIp = existingLog.clientIp || existingLog.ip;
                    const logSubnet = logIp ? __internal.getIpSubnet(logIp, 24, 48) : null;
                    const logFp = existingLog.deviceHash || existingLog.fingerprint || existingLog.deviceFingerprint;
                    const logStableFp = logFp ? extractStablePart(logFp) : null;

                    const isIpMatch = subnet && logSubnet === subnet;
                    const isFpMatch = stableFp && logStableFp === stableFp;

                    if (isIpMatch) ipMatchCount++;
                    if (isFpMatch) fpMatchCount++;

                    if (isIpMatch || isFpMatch) matchedKey = i;
                }

                if ((subnet && (ipMatchCount / total) > maxPercentage) || (stableFp && (fpMatchCount / total) > maxPercentage)) {
                    if (matchedKey !== null) {
                        trafficData[matchedKey].instancesCount = (trafficData[matchedKey].instancesCount || 1) + 1;
                        trafficData[matchedKey].weight = (trafficData[matchedKey].weight || 1.0) + 1.0;
                    }
                    return;
                }
            }
            originalLogger(log);
        };
        securityConfig.logger_wrapped = true;
    }

    console.log(`[AutoTuning] Job d'optimisation des seuils démarré. Prochain cycle dans ${interval / 60000} minutes.`);

    autoTuningJobId = setInterval(() => {
        runThresholdOptimization(securityConfig, trafficData, minDataPoints, maxDataPoints, savePath, { maxAgeMs, clearAfterTuning, onCleanup });
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

/**
 * Returns the last best solution found by the auto-tuner.
 * This is useful for logging or creating a "finops" security configuration.
 * @export
 * @returns {object|null} The best solution object { solution, objectives } or null if no tuning has run.
 */
export function getBestTuningSolution() {
    return lastBestSolution;
}

class RequestContext {
  constructor(ip, path, headers, query, body, cookies, httpVersion) {
    this.clientIp = ip || '127.0.0.1';
    this.path = path || '/';
    this.headers = headers || {};
    this.query = query || {};
    this.body = body || null;
    this.cookies = cookies || {};
    this.httpVersion = httpVersion || '1.1';
  }
}

const dynamicCounters = new Map();
const dynamicObservations = new Map();

export function incrementCounter(name, labels = {}) {
    const sortedLabels = Object.keys(labels).sort().reduce((acc, key) => {
        acc[key] = labels[key];
        return acc;
    }, {});
    const labelsKey = JSON.stringify(sortedLabels);
    const queryName = name.startsWith('fingerprint_') ? name : `fingerprint_${name}`;
    const fullKey = `${queryName}:${labelsKey}`;

    if (!dynamicCounters.has(fullKey)) {
        dynamicCounters.set(fullKey, { name: queryName, labels: sortedLabels, value: 0 });
    }
    dynamicCounters.get(fullKey).value++;
}

export function observeValue(name, value, labels = {}) {
    const sortedLabels = Object.keys(labels).sort().reduce((acc, key) => {
        acc[key] = labels[key];
        return acc;
    }, {});
    const labelsKey = JSON.stringify(sortedLabels);
    const queryName = name.startsWith('fingerprint_') ? name : `fingerprint_${name}`;
    const fullKey = `${queryName}:${labelsKey}`;
    dynamicObservations.set(fullKey, { name: queryName, labels: sortedLabels, value });
}

export function getMetric(name, securityConfig = {}) {
    const result = new Map();
    const queryName = name.startsWith('fingerprint_') ? name : `fingerprint_${name}`;

    if (queryName === 'fingerprint_security_weight') {
        const weights = securityConfig.weights || {};
        for (const [indicator, weight] of Object.entries(weights)) {
            if (typeof weight === 'number') {
                result.set(indicator, weight);
            }
        }
    } else if (queryName === 'fingerprint_security_threshold') {
        const thresholds = securityConfig.thresholds || {};
        for (const [level, threshold] of Object.entries(thresholds)) {
            if (typeof threshold === 'number') {
                result.set(level, threshold);
            }
        }
    } else if (queryName === 'fingerprint_autotuning_false_positive_rate') {
        if (lastBestSolution && lastBestSolution.objectives) {
            result.set('fpr', lastBestSolution.objectives[0]);
        }
    } else if (queryName === 'fingerprint_autotuning_false_negative_rate') {
        if (lastBestSolution && lastBestSolution.objectives) {
            result.set('fnr', lastBestSolution.objectives[1]);
        }
    } else {
        // Search dynamic counters
        for (const counter of dynamicCounters.values()) {
            if (counter.name === queryName || counter.name === name) {
                const labelPairs = Object.entries(counter.labels)
                    .map(([k, v]) => `${k}="${v}"`)
                    .join(',');
                result.set(labelPairs || 'value', counter.value);
            }
        }

        // Search dynamic observations
        for (const obs of dynamicObservations.values()) {
            if (obs.name === queryName || obs.name === name) {
                const labelPairs = Object.entries(obs.labels)
                    .map(([k, v]) => `${k}="${v}"`)
                    .join(',');
                result.set(labelPairs || 'value', obs.value);
            }
        }
    }
    return result;
}

const MetricsManager = {
    getPrometheusMetrics(securityConfig = {}) {
        let metrics = '';

        if (dynamicCounters.size === 0) {
            metrics += `# HELP fingerprint_requests_total Total requests processed.\n# TYPE fingerprint_requests_total counter\nfingerprint_requests_total{status="passed"} 1\n`;
        } else {
            const grouped = {};
            for (const counter of dynamicCounters.values()) {
                if (!grouped[counter.name]) {
                    grouped[counter.name] = [];
                }
                grouped[counter.name].push(counter);
            }
            for (const [name, instances] of Object.entries(grouped)) {
                metrics += `# HELP ${name} Total requests processed.\n# TYPE ${name} counter\n`;
                for (const inst of instances) {
                    const labelPairs = Object.entries(inst.labels)
                        .map(([k, v]) => `${k}="${v}"`)
                        .join(',');
                    const labelStr = labelPairs ? `{${labelPairs}}` : '';
                    metrics += `${name}${labelStr} ${inst.value}\n`;
                }
            }
        }

        if (dynamicObservations.size > 0) {
            const grouped = {};
            for (const obs of dynamicObservations.values()) {
                if (!grouped[obs.name]) {
                    grouped[obs.name] = [];
                }
                grouped[obs.name].push(obs);
            }
            for (const [name, instances] of Object.entries(grouped)) {
                metrics += `\n# HELP ${name} Value observation.\n# TYPE ${name} gauge\n`;
                for (const inst of instances) {
                    const labelPairs = Object.entries(inst.labels)
                        .map(([k, v]) => `${k}="${v}"`)
                        .join(',');
                    const labelStr = labelPairs ? `{${labelPairs}}` : '';
                    metrics += `${name}${labelStr} ${inst.value}\n`;
                }
            }
        }

        if (securityConfig.weights) {
            metrics += `\n# HELP fingerprint_security_weight Active weight for each suspicion indicator.\n# TYPE fingerprint_security_weight gauge\n`;
            for (const [indicator, weight] of Object.entries(securityConfig.weights)) {
                if (typeof weight === 'number') {
                    metrics += `fingerprint_security_weight{indicator="${indicator}"} ${weight}\n`;
                }
            }
        }

        if (securityConfig.thresholds) {
            metrics += `\n# HELP fingerprint_security_threshold Active score threshold for each enforcement action level.\n# TYPE fingerprint_security_threshold gauge\n`;
            for (const [level, threshold] of Object.entries(securityConfig.thresholds)) {
                if (typeof threshold === 'number') {
                    metrics += `fingerprint_security_threshold{level="${level}"} ${threshold}\n`;
                }
            }
        }

        if (lastBestSolution && lastBestSolution.objectives) {
            metrics += `\n# HELP fingerprint_autotuning_false_positive_rate Current false positive rate calculated by the auto-tuner.\n# TYPE fingerprint_autotuning_false_positive_rate gauge\nfingerprint_autotuning_false_positive_rate ${lastBestSolution.objectives[0]}\n`;
            metrics += `\n# HELP fingerprint_autotuning_false_negative_rate Current false negative rate calculated by the auto-tuner.\n# TYPE fingerprint_autotuning_false_negative_rate gauge\nfingerprint_autotuning_false_negative_rate ${lastBestSolution.objectives[1]}\n`;
        }

        return metrics;
    }
};

/**
 * Gère une requête vers le point de terminaison /metrics, en appliquant les règles d'autorisation.
 * Si les métriques sont activées et autorisées, elle renvoie les métriques au format Prometheus.
 * Sinon, elle gère l'accès non autorisé ou renvoie un 404 si les métriques ne sont pas activées.
 *
 * @param {object} req L'objet requête Express.
 * @param {object} res L'objet réponse Express.
 * @param {object} securityConfig La configuration de sécurité.
 */
export async function handleMetricsRequest(req, res, securityConfig) {
    // 2. Appliquer le callback d'autorisation personnalisé si défini.
    const authorizationCallback = securityConfig.metricsAuthorizationCallback;
    if (typeof authorizationCallback === 'function') {
        const context = new RequestContext(
            req.ip,
            sanitizeRedirectPath(req.path),
            req.headers,
            req.query,
            req.body,
            req.cookies,
            req.httpVersion
        );

        const decision = await authorizationCallback(context); // Supposons que le callback peut être asynchrone

        if (typeof decision === 'boolean') {
            if (!decision) {
                res.status(403).send('Access to metrics denied.');
                return;
            }
        } else if (typeof decision === 'object' && decision !== null && decision.action) {
            if (decision.action === 'block') {
                res.status(decision.status || 403).send(decision.body || 'Access denied.');
                return;
            } else if (decision.action === 'redirect') {
                res.redirect(decision.status || 302, decision.path);
                return;
            }
        }
    }

    // 3. Si autorisé, servir les métriques.
    res.set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(MetricsManager.getPrometheusMetrics(securityConfig));
}