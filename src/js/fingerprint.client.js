import {cyrb53 as jsCyrb53, FingerprintBuilder} from './fingerprint.builder.js';
import {solveChallenge} from './pow.solver.js';

function secureRandom() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
        const array = new Uint32Array(1);
        globalThis.crypto.getRandomValues(array);
        return array[0] / 0xffffffff;
    }
    return Math.random();
}

// Variable storing the active hash function.
// Defaults to the JavaScript implementation.
let activeCyrb53 = jsCyrb53;
let derivedKey = null;

async function negotiateSessionKey() {
    if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) return;
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveKey"]
        );
        const clientPubKeyBuffer = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
        const clientPubKeyHex = Array.from(new Uint8Array(clientPubKeyBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');

        const response = await fetch(window.location.pathname + '?fp_handshake=1', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-client-ephemeral-key': clientPubKeyHex
            },
            body: JSON.stringify({ fp: ClientLibrary.getDeviceFingerprint() })
        });

        if (!response || !response.headers) return;
        let serverPubKeyHex = null;
        if (typeof response.headers.get === 'function') {
            serverPubKeyHex = response.headers.get('x-server-ephemeral-key');
        } else if (typeof response.headers === 'object') {
            serverPubKeyHex = response.headers['x-server-ephemeral-key'] || response.headers['X-Server-Ephemeral-Key'];
        }
        if (serverPubKeyHex) {
            const serverPubKeyBuffer = new Uint8Array(
                serverPubKeyHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
            );
            const serverPubKey = await window.crypto.subtle.importKey(
                "raw",
                serverPubKeyBuffer,
                { name: "ECDH", namedCurve: "P-256" },
                true,
                []
            );
            derivedKey = await window.crypto.subtle.deriveKey(
                { name: "ECDH", public: serverPubKey },
                keyPair.privateKey,
                { name: "HMAC", hash: "SHA-256", length: 256 },
                true,
                ["sign"]
            );
            console.log('[Fingerprint] Cryptographic session negotiated successfully.');
        }
    } catch (e) {
        console.warn('[Fingerprint] Cryptographic session negotiation failed:', e);
    }
}

async function signMetrics(metricsObj) {
    if (!derivedKey) return metricsObj;
    try {
        const copy = JSON.parse(JSON.stringify(metricsObj));
        delete copy.signature;
        const dataToSign = new TextEncoder().encode(JSON.stringify(copy));
        const signatureBuffer = await window.crypto.subtle.sign(
            "HMAC",
            derivedKey,
            dataToSign
        );
        copy.signature = Array.from(new Uint8Array(signatureBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
        return copy;
    } catch (e) {
        return metricsObj;
    }
}

const DB_NAME = 'wasm-cache-db';
const DB_VERSION = 1;
const STORE_NAME = 'wasm-modules';

const genRandStr = (len = 8) => {
    return Array.from({ length: len }, () => String.fromCharCode(97 + Math.floor(secureRandom() * 26))).join('');
};

function getCachedWasm(url) {
    return new Promise((resolve) => {
        if (typeof indexedDB === 'undefined') return resolve(null);
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };
        request.onsuccess = (e) => {
            const db = e.target.result;
            try {
                const transaction = db.transaction(STORE_NAME, 'readonly');
                const store = transaction.objectStore(STORE_NAME);
                const getReq = store.get(url);
                getReq.onsuccess = () => resolve(getReq.result);
                getReq.onerror = () => resolve(null);
            } catch (err) {
                resolve(null);
            }
        };
        request.onerror = () => resolve(null);
    });
}

function cacheWasm(url, data) {
    return new Promise((resolve) => {
        if (typeof indexedDB === 'undefined') return resolve(false);
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) {
                db.createObjectStore(STORE_NAME);
            }
        };
        request.onsuccess = (e) => {
            const db = e.target.result;
            try {
                const transaction = db.transaction(STORE_NAME, 'readwrite');
                const store = transaction.objectStore(STORE_NAME);
                store.put(data, url);
                transaction.oncomplete = () => resolve(true);
                transaction.onerror = () => resolve(false);
            } catch (err) {
                resolve(false);
            }
        };
        request.onerror = () => resolve(false);
    });
}

const ClientLibrary = {
    // Cache to avoid recalculating hardware constants
    _cachedBuilder: null,
    /**
     * @private
     * Dispatches a custom event from the window object.
     * @param {string} eventName - The name of the event.
     * @param {object} [detail={}] - The data to include in the event's detail property.
     */
    _dispatchEvent(eventName, detail = {}) {
        if (typeof window === 'undefined') return;
        const CustomEventCtor = window.CustomEvent || (typeof CustomEvent !== 'undefined' ? CustomEvent : null);
        if (!CustomEventCtor) return;
        try {
            const event = new CustomEventCtor(`fingerprint:${eventName}`, { detail });
            window.dispatchEvent(event);
        } catch (e) {
        }
    },

    /**
     * Checks if native JavaScript prototypes have been tampered with or hooked (Frida, Puppeteer Stealth).
     */
    detectTamperedPrototypes() {
        const checkNative = (obj, method) => {
            try {
                if (!obj) return false;
                const fn = obj[method];
                if (!fn) return false;
                const str = Function.prototype.toString.call(fn);
                if (!str.includes('[native code]')) return true; // Standard JS hook
                const desc = Object.getOwnPropertyDescriptor(obj, method);
                if (desc && (!desc.writable && !desc.configurable && desc.value)) return false;
                return false;
            } catch (e) {
                return true;
            }
        };

        const win = typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : null);
        if (!win) return false;

        const htmlCanvas = typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement : win.HTMLCanvasElement;
        const canvas2d = typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D : win.CanvasRenderingContext2D;
        const webgl = typeof WebGLRenderingContext !== 'undefined' ? WebGLRenderingContext : win.WebGLRenderingContext;

        const isFetchTampered = () => {
            if (ClientLibrary._isFetchPatched) {
                if (ClientLibrary._originalFetch) {
                    return !Function.prototype.toString.call(ClientLibrary._originalFetch).includes('[native code]');
                }
                return false;
            }
            return checkNative(win, 'fetch');
        };

        return checkNative(htmlCanvas?.prototype, 'toDataURL') ||
               checkNative(canvas2d?.prototype, 'getImageData') ||
               checkNative(webgl?.prototype, 'getParameter') ||
               isFetchTampered();
    },

    /**
     * Internal wrapper for the active hash function.
     * @private
     */
    _hasher: (str, seed) => activeCyrb53(str, seed),

    /**
     * Generates a Schnorr Zero-Knowledge Proof (ZKP) of the device fingerprint.
     * Ensures compatibility across JS, PHP, and Java verification engines.
     * @param {string} fingerprint - Device fingerprint string.
     * @returns {Promise<string>} Proof in hex format "y:t:s".
     */
    async generateZkpProof(fingerprint) {
        const ZKP_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663n;
        const ZKP_G = 2n;
        const cryptoObj = window.crypto || window.msCrypto;

        const sha256Hex = async (str) => {
            const encoder = new TextEncoder();
            const data = encoder.encode(str);
            const hashBuffer = await cryptoObj.subtle.digest('SHA-256', data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        };

        const modPow = (base, exponent, modulus) => {
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
        };

        const xHex = await sha256Hex(fingerprint);
        const x = BigInt('0x' + xHex) % ZKP_P;
        const y = modPow(ZKP_G, x, ZKP_P);
        const randomBytes = new Uint8Array(32);
        cryptoObj.getRandomValues(randomBytes);
        let vHex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        let v = BigInt('0x' + vHex) % (ZKP_P - 1n);
        if (v === 0n) v = 1n;
        const t = modPow(ZKP_G, v, ZKP_P);
        const cStr = ZKP_G.toString() + y.toString() + t.toString();
        const cHex = await sha256Hex(cStr);
        const c = BigInt('0x' + cHex) % ZKP_P;
        const s = (v + c * x) % (ZKP_P - 1n);

        return `${y.toString(16)}:${t.toString(16)}:${s.toString(16)}`;
    },

    /**
     * Generates the current device fingerprint.
     */
    getDeviceFingerprint() {
        if (typeof window === "undefined") {
            console.error("getDeviceFingerprint can only be called on the client-side.");
            return "";
        }
        
        if (!this._cachedBuilder) {
            const nav = window.navigator;
            const screen = window.screen;

            this._cachedBuilder = new FingerprintBuilder();

            // 1. Hardware (Very stable): Cores, RAM, GPU, Touch
            this._cachedBuilder.add(
                "hw",
                `${nav.hardwareConcurrency}_${nav.deviceMemory}_${nav.maxTouchPoints}`,
            );

            // 2. Geo/Locale (Stable unless traveling/VPN): Timezone, Language
            this._cachedBuilder.add(
                "geo",
                `${Intl.DateTimeFormat().resolvedOptions().timeZone}_${nav.language}_${new Date().getTimezoneOffset()}`,
            );

            // 3. Screen (Stable unless monitor/zoom changes): Dimensions, ColorDepth
            this._cachedBuilder.add(
                "scr",
                `${screen.width}x${screen.height}_${screen.colorDepth}`,
            );

            // 4. Platform (Stable) : OS, Engine
            this._cachedBuilder.add("os", nav.platform);

            // 5. Graphics (WebGL Vendor/Renderer) - Invariant matériel fort
            try {
                const canvas = document.createElement("canvas");
                const gl =
                    canvas.getContext("webgl2") ||
                    canvas.getContext("webgl") ||
                    canvas.getContext("experimental-webgl");
                if (gl) {
                    const debugInfo = gl.getExtension("WEBGL_debug_renderer_info");
                    if (debugInfo) {
                        const vendor = gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
                        const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                        this._cachedBuilder.add("gpu", `${vendor}_${renderer}`);
                    }
                }
            } catch (e) {
            }

            // 6. Canvas Fingerprinting (Rendering quirks)
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
                    ctx.fillText("fingerprint", 2, 15);
                    ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                    ctx.fillText("fingerprint", 4, 17);
                    this._cachedBuilder.add("cvs", canvas.toDataURL());
                }
            } catch (e) {
            }

            // 7. Detection of Chrome DevTools Protocol (CDP) artifacts
            // Injected by automation tools
            const cdpFootprints = [
                'cdc_adoQpoasnfa76pfcZLmcfl_Array',
                'cdc_adoQpoasnfa76pfcZLmcfl_Promise',
                'cdc_adoQpoasnfa76pfcZLmcfl_Symbol',
                '$cdc_asdjflasutopfhvcZLmcfl_',
                '_selenium',
                '_driver'
            ];
            if (cdpFootprints.some(fp => window[fp])) {
                this._cachedBuilder.add("cdp", "true");
            }

            // 8. Bot Detection (Hidden indicators)
            if (nav.webdriver) this._cachedBuilder.add("bot", "true");
            if (ClientLibrary.detectTamperedPrototypes()) {
                this._cachedBuilder.add("tampered", "true");
            }
        }

        return this._cachedBuilder.toString();
    },

    /**
     * Generates a request signature including context.
     * @param {object} payload
     */
    /**
     * Génère une signature de requête incluant le contexte.
     * @param {object} payload
     */
    generateRequestSignature(payload = {}) {
        const deviceFp = this.getDeviceFingerprint();
        const sortedPayload = Object.keys(payload)
            .sort()
            .map((k) => `${k}=${payload[k]}`)
            .join("&");
        const payloadHash = this._hasher(sortedPayload);
        return `${deviceFp}|req:${payloadHash}`;
    },

    /**
     * Generates an HMAC-SHA256 signature using the Web Crypto API.
     * @param {object} payload - Data payload to sign.
     * @param {string} secret - Shared secret key.
     * @returns {Promise<string>} Hexadecimal signature.
     */
    async generateClientSideSignature(payload, secret) {
        const sortedPayload = Object.keys(payload).sort().map((k) => `${k}=${payload[k]}`).join("&");
        const encoder = new TextEncoder();
        const key = await window.crypto.subtle.importKey("raw", encoder.encode(secret), {
            name: "HMAC",
            hash: "SHA-256"
        }, false, ["sign"]);
        const signatureBuffer = await window.crypto.subtle.sign("HMAC", key, encoder.encode(sortedPayload));
        const hashArray = Array.from(new Uint8Array(signatureBuffer));
        return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    },

    /**
     * @internal
     * Resets the cached fingerprint builder. Used for testing purposes.
     */
    _resetCache() {
        // Reset hasher to default JS implementation.
        activeCyrb53 = jsCyrb53;
        this._cachedBuilder = null;
    },

    /**
     * Injects invisible phantom interactive elements to trap bots (focus/hover).
     */
    injectPhantomTraps() {
        if (typeof document === 'undefined') return;

        // Create a phantom interactive element
        const phantom = document.createElement('a');
        phantom.href = '#';
        // Random deceptive name to attract automated link/form parsers
        const phantomNames = ['sys-session-recovery', 'auth-token-refresh', 'debug-console-login', 'admin-portal-access', 'security-bypass-bypass', 'recovery-key-session', 'api-key-test', 'client-secrets-access'];
        phantom.id = phantomNames[Math.floor(secureRandom() * phantomNames.length)] + '-' + genRandStr(6);
        phantom.className = genRandStr(8);
        phantom.tabIndex = 0; // In natural tab flow
        phantom.setAttribute('aria-hidden', 'true'); // Hidden from legitimate screen readers

        // Invisible yet interactive style (1px x 1px, nearly transparent)
        phantom.style.position = 'fixed';
        phantom.style.top = '1px';
        phantom.style.left = '1px';
        phantom.style.width = '1px';
        phantom.style.height = '1px';
        phantom.style.opacity = '0.001';
        phantom.style.zIndex = '99999';
        phantom.style.overflow = 'hidden';
        phantom.style.pointerEvents = 'auto';

        const triggerTrap = () => {
            this.onHoneypotTrigger();
        };

        phantom.addEventListener('focus', triggerTrap, { passive: true });
        phantom.addEventListener('mouseover', triggerTrap, { passive: true });

        // Polymorphic DOM insertion of the phantom trap
        const nestingOptions = [
            () => document.body.appendChild(phantom),
            () => {
                const wrapper = document.createElement(secureRandom() > 0.5 ? 'span' : 'div');
                wrapper.className = genRandStr(8);
                wrapper.style.position = 'absolute';
                wrapper.style.width = '0';
                wrapper.style.height = '0';
                wrapper.style.overflow = 'hidden';
                wrapper.appendChild(phantom);
                document.body.appendChild(wrapper);
            }
        ];
        nestingOptions[Math.floor(secureRandom() * nestingOptions.length)]();
    },

    /**
     * Measures gyroscope/accelerometer noise to detect phone farm racks.
     */
    startMotionTracker() {
        if (this._motionTrackerAttached || typeof window === 'undefined') return;
        this._motionTrackerAttached = true;
        const motionSamples = [];
        const handleMotion = (e) => {
            const acc = e.accelerationIncludingGravity || e.acceleration;
            if (!acc) return;
            const mag = Math.sqrt((acc.x || 0)**2 + (acc.y || 0)**2 + (acc.z || 0)**2);
            motionSamples.push(mag);
            if (motionSamples.length > 20) motionSamples.shift();
            if (motionSamples.length >= 10) {
                const avg = motionSamples.reduce((a, b) => a + b, 0) / motionSamples.length;
                const variance = motionSamples.reduce((a, b) => a + (b - avg)**2, 0) / motionSamples.length;
                metrics.motionVariance = Math.round(variance * 10000) / 10000;
            }
        };
        try {
            window.addEventListener('devicemotion', handleMotion, { passive: true });
        } catch (e) {}
    },

    /**
     * Starts tracking touch events on mobile/tablet devices.
     */
    startTouchEventTracker() {
        if (this._touchTrackerAttached) return;
        this._touchTrackerAttached = true;

        const handleTouch = (e) => {
            if (touchMovementsHistory.length >= TOUCH_HISTORY_MAX) {
                touchMovementsHistory.shift();
            }
            const touch = e.touches[0] || e.changedTouches[0];
            if (!touch) return;

            const radiusX = touch.radiusX || 0;
            const radiusY = touch.radiusY || 0;
            const radius = (radiusX + radiusY) / 2;
            const force = touch.force || touch.webkitForce || 0;

            touchMovementsHistory.push({
                x: touch.clientX,
                y: touch.clientY,
                t: performance.now(),
                p: force,
                r: radius,
                num: e.touches.length
            });
        };

        document.addEventListener('touchstart', handleTouch, { passive: true });
        document.addEventListener('touchmove', handleTouch, { passive: true });
        document.addEventListener('touchend', handleTouch, { passive: true });
    },

    /**
     * Starts tracking display regularity (V-Sync/rAF) to detect software framebuffers lacking V-Sync.
     */
    startRenderingTracker() {
        if (this._renderingTrackerAttached) return;
        this._renderingTrackerAttached = true;

        if (typeof window === 'undefined' || !window.requestAnimationFrame) return;

        const rAfTimestamps = [];
        let lastTime = performance.now();
        const maxSamples = 15;

        const checkOffscreenAnom = () => {
            try {
                const htmlCanvas = typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement : window.HTMLCanvasElement;
                if ('OffscreenCanvas' in window && htmlCanvas?.prototype?.transferControlToOffscreen) {
                    const nativeToString = Function.prototype.toString.call(htmlCanvas.prototype.transferControlToOffscreen);
                    return !nativeToString.includes('[native code]');
                }
            } catch (e) {}
            return false;
        };

        const loop = (time) => {
            const delta = time - lastTime;
            lastTime = time;
            if (rAfTimestamps.length < maxSamples) {
                if (rAfTimestamps.length > 0) { // Skip first delta
                    rAfTimestamps.push(delta);
                }
                window.requestAnimationFrame(loop);
            } else {
                const avg = rAfTimestamps.reduce((a, b) => a + b, 0) / rAfTimestamps.length;
                const sqDiffs = rAfTimestamps.map(v => Math.pow(v - avg, 2));
                const avgSqDiff = sqDiffs.reduce((a, b) => a + b, 0) / sqDiffs.length;
                
                metrics.rendering = {
                    fps: Math.round((1000 / avg) * 100) / 100,
                    jitter: Math.round(Math.sqrt(avgSqDiff) * 100) / 100,
                    offscreenAnom: checkOffscreenAnom()
                };
            }
        };
        window.requestAnimationFrame(loop);
    },

    /**
     * Initializes persistent Proof-of-Space allocation in local IndexedDB.
     */
    async initializeSpace(seed, sizeMb) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('pospace-db', 1);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('blocks')) {
                    db.createObjectStore('blocks');
                }
            };
            request.onsuccess = async (e) => {
                const db = e.target.result;
                const tx = db.transaction('blocks', 'readwrite');
                const store = tx.objectStore('blocks');
                
                const maxBlocks = sizeMb * 1024;
                const countReq = store.count();
                countReq.onsuccess = async () => {
                    if (countReq.result < maxBlocks) {
                        for (let i = 0; i < maxBlocks; i++) {
                            const block = new Uint8Array(1024);
                            let h = 5381;
                            for (let j = 0; j < seed.length; j++) {
                                h = (h << 5) + h + seed.charCodeAt(j);
                            }
                            h = (h << 5) + h + i;
                            for (let k = 0; k < 1024; k++) {
                                h = Math.imul(h ^ k, 1597334677);
                                block[k] = h & 0xff;
                            }
                            store.put(block, i);
                        }
                    }
                    resolve();
                };
            };
            request.onerror = () => reject(new Error("Failed to open pospace database"));
        });
    },

    /**
     * Reads a specific block from local IndexedDB formatted as hex.
     */
    async readSpaceBlock(blockIdx) {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('pospace-db', 1);
            request.onsuccess = (e) => {
                const db = e.target.result;
                const tx = db.transaction('blocks', 'readonly');
                const store = tx.objectStore('blocks');
                const getReq = store.get(blockIdx);
                getReq.onsuccess = () => {
                    const block = getReq.result;
                    if (block) {
                        const hex = Array.from(block).map(b => b.toString(16).padStart(2, '0')).join('');
                        resolve(hex);
                    } else {
                        reject(new Error("Block not found"));
                    }
                };
                getReq.onerror = () => reject(getReq.error);
            };
            request.onerror = () => reject(new Error("Failed to open pospace database"));
        });
    },

    /**
     * Solves Proof-of-Space by optionally combining a peer's block.
     */
    async solveSpaceChallenge(seed, queries, nonce, clientSecret, peerBlock = '') {
        const blocks = [];
        for (const idx of queries) {
            const blockHex = await this.readSpaceBlock(idx);
            blocks.push(blockHex);
        }
        let finalPayload = blocks.join('') + peerBlock + nonce + ":" + clientSecret;
        const encoder = new TextEncoder();
        const data = encoder.encode(finalPayload);
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    },

    /**
     * Starts tracking mouse movements to evaluate entropy.
     * Call once per page lifecycle.
     */
    startMouseEntropyTracker() {
        // Utiliser un drapeau pour éviter d'attacher l'écouteur plusieurs fois
        if (this._mouseTrackerAttached) return;
        this._mouseTrackerAttached = true;
 
        document.addEventListener('mousemove', (e) => {
            // Capture trajectory points {x, y, t}
            if (mouseMovementsHistory.length >= MOUSE_HISTORY_MAX) {
                // Cap history size to prevent unbounded memory growth
                mouseMovementsHistory.shift();
            }
            mouseMovementsHistory.push({
                x: e.clientX,
                y: e.clientY,
                t: performance.now()
            });
        }, {passive: true});
    },

    /**
     * Starts tracking keystroke dynamics to evaluate dwell and flight times.
     * Call once per page lifecycle.
     */
    startKeystrokeDynamicsTracker() {
        // S'assurer de ne pas attacher l'écouteur plusieurs fois
        if (this._keystrokeTrackerAttached) return;
        this._keystrokeTrackerAttached = true;

        const activeKeys = new Map();
        let lastKeyDownTime = 0;
        let lastKeyName = '';

        document.addEventListener('keydown', (e) => {
            const now = performance.now();
            const key = e.key;
            const code = e.code;
            if (!key && !code) return;

            const keyIdentifier = code || key;

            // Prevent key repeat triggering multiple events
            if (activeKeys.has(keyIdentifier)) return;
            activeKeys.set(keyIdentifier, now);

            if (keystrokeTimestamps.length > 0) {
                const lastTimestamp = keystrokeTimestamps[keystrokeTimestamps.length - 1];
                const latency = now - lastTimestamp;
                if (latency > 10 && latency < 2000) {
                    if (keystrokeLatencies.length >= KEYSTROKE_HISTORY_MAX) {
                        keystrokeLatencies.shift();
                    }
                    keystrokeLatencies.push(latency);
                }
            }
            keystrokeTimestamps.push(now);

            // Flight Time (KeyDown to KeyDown)
            if (lastKeyDownTime > 0) {
                const flightTime = now - lastKeyDownTime;
                if (flightTime > 10 && flightTime < 2000) {
                    if (keystrokeFlightTimes.length >= KEYSTROKE_HISTORY_MAX) {
                        keystrokeFlightTimes.shift();
                    }
                    const digraph = lastKeyName ? this._hasher(lastKeyName + "_" + keyIdentifier).toString() : "unknown";
                    keystrokeFlightTimes.push({ digraph, time: flightTime });
                }
            }
            lastKeyDownTime = now;
            lastKeyName = keyIdentifier;
        }, {passive: true});

        document.addEventListener('keyup', (e) => {
            const now = performance.now();
            const key = e.key;
            const code = e.code;
            if (!key && !code) return;

            const keyIdentifier = code || key;

            if (activeKeys.has(keyIdentifier)) {
                const pressTime = activeKeys.get(keyIdentifier);
                const dwellTime = now - pressTime;
                activeKeys.delete(keyIdentifier);

                if (dwellTime > 5 && dwellTime < 1000) {
                    if (keystrokeDwellTimes.length >= KEYSTROKE_HISTORY_MAX) {
                        keystrokeDwellTimes.shift();
                    }
                    keystrokeDwellTimes.push(dwellTime);
                }
            }
        }, {passive: true});
    },

    /**
     * Starts tracking click events to analyze position variance.
     * @private
     */
    startClickTracker() {
        if (this._clickTrackerAttached) return;
        this._clickTrackerAttached = true;

        document.addEventListener('click', (e) => {
            if (clicksHistory.length >= CLICKS_HISTORY_MAX) {
                clicksHistory.shift();
            }
            // Generate a simple identifier for the target element
            const target = e.target;
            const targetId = target.id || target.name || target.tagName;

            clicksHistory.push({
                x: e.clientX,
                y: e.clientY,
                t: performance.now(),
                targetId: this._hasher(targetId) // Hash the ID to keep it short and consistent
            });
        }, { passive: true });
    },
    /**
     * Initializes or resets client-side honeypots for immediate detection.
     * Previous listeners are removed before attaching new ones.
     * @param {string[]} honeypotFieldNames - Hidden form field names.
     */
    initializeHoneypots(honeypotFieldNames) {
        // 1. Clean up existing listeners
        activeHoneypotListeners.forEach((listener, field) => {
            field.removeEventListener('input', listener);
        });
        activeHoneypotListeners.clear();

        // 2. Attach new listeners to existing DOM elements
        honeypotFieldNames.forEach(fieldName => {
            const field = document.querySelector(`[name="${fieldName}"]`);
            if (field) {
                const listener = () => {
                    this.onHoneypotTrigger();
                    field.removeEventListener('input', listener);
                };
                field.addEventListener('input', listener);
                activeHoneypotListeners.set(field, listener);
            }
        });

        // 3. Generate trap inputs inside a closed Shadow DOM
        if (typeof document !== 'undefined' && honeypotFieldNames.length > 0) {
            const host = document.createElement('div');
            host.setAttribute('aria-hidden', 'true');
            host.style.position = 'absolute';
            host.style.width = '0';
            host.style.height = '0';
            host.style.overflow = 'hidden';

            const shadow = host.attachShadow({ mode: 'closed' });

            // Randomize classes, CSS variables, and layout tags
            const wrapperClass = genRandStr(10);
            const posStateVar = `--${genRandStr(8)}`;
            const offValVar = `--${genRandStr(8)}`;
            const visStateVar = `--${genRandStr(8)}`;
            const scaleValVar = `--${genRandStr(8)}`;

            const style = document.createElement('style');
            style.textContent = `
              :host {
                ${posStateVar}: absolute;
                ${offValVar}: -9999px;
                ${visStateVar}: hidden;
                ${scaleValVar}: 0;
              }
              .${wrapperClass} {
                position: var(${posStateVar});
                left: var(${offValVar});
                top: var(${offValVar});
                visibility: var(${visStateVar});
                transform: scale(var(${scaleValVar}));
              }
            `;
            shadow.appendChild(style);

            const wrapperTags = ['div', 'section', 'p', 'span', 'form', 'main'];
            const selectedWrapperTag = wrapperTags[Math.floor(secureRandom() * wrapperTags.length)];
            const wrapper = document.createElement(selectedWrapperTag);
            wrapper.className = wrapperClass;

            honeypotFieldNames.forEach(fieldName => {
                const label = document.createElement('label');
                label.textContent = fieldName;
                const input = document.createElement('input');
                input.type = 'text';
                input.name = fieldName;
                input.tabIndex = -1;
                input.className = genRandStr(6);
                input.id = genRandStr(8);
                input.autocomplete = 'off';

                const trigger = () => {
                    this.onHoneypotTrigger();
                };

                input.addEventListener('input', trigger, { passive: true });
                input.addEventListener('change', trigger, { passive: true });
                input.addEventListener('focus', trigger, { passive: true });

                // Polymorphic nesting of label and input
                const nestingType = Math.floor(secureRandom() * 3);
                if (nestingType === 1) {
                    label.appendChild(input);
                    wrapper.appendChild(label);
                } else if (nestingType === 2) {
                    const innerContainer = document.createElement(secureRandom() > 0.5 ? 'span' : 'div');
                    innerContainer.className = genRandStr(5);
                    innerContainer.appendChild(label);
                    innerContainer.appendChild(input);
                    wrapper.appendChild(innerContainer);
                } else {
                    wrapper.appendChild(label);
                    wrapper.appendChild(input);
                }
            });

            shadow.appendChild(wrapper);
            document.body.appendChild(host);
        }
    },
    /**
     * Silently requests FIDO2 hardware attestation (WebAuthn)
     * to anchor physical device identity via TPM / Secure Enclave.
     * @returns {Promise<object|null>}
     */
    async getWebAuthnAnchor() {
        const win = typeof window !== 'undefined' ? window : null;
        if (!win || !win.PublicKeyCredential) return null;
        try {
            const isPlatformAvailable = await win.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            if (!isPlatformAvailable) return null;

            const storedCredIdBase64 = localStorage.getItem('fp_webauthn_cred_id');
            const challenge = new Uint8Array([109, 101, 116, 114, 105, 99, 115, 95, 97, 110, 99, 104, 111, 114, 95, 115, 101, 99, 117, 114, 101]); // Static stable challenge

            if (storedCredIdBase64) {
                // Silent assertion attempt (Authentication)
                const credentialId = Uint8Array.from(atob(storedCredIdBase64), c => c.charCodeAt(0));
                const assertion = await navigator.credentials.get({
                    publicKey: {
                        challenge,
                        allowCredentials: [{
                            id: credentialId,
                            type: 'public-key'
                        }],
                        userVerification: 'discouraged',
                        timeout: 1000
                    }
                });
                if (assertion) {
                    return {
                        type: 'assertion',
                        credentialId: storedCredIdBase64,
                        signature: btoa(String.fromCharCode(...new Uint8Array(assertion.response.signature))),
                        authenticatorData: btoa(String.fromCharCode(...new Uint8Array(assertion.response.authenticatorData))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(assertion.response.clientDataJSON)))
                    };
                }
            } else {
                // Silent creation attempt (Registration)
                const options = {
                    publicKey: {
                        challenge,
                        rp: { name: window.location.hostname, id: window.location.hostname },
                        user: {
                            id: new Uint8Array([102, 112, 105, 100]),
                            name: 'silent-device-anchor',
                            displayName: 'Hardware Device Anchor'
                        },
                        pubKeyCredParams: [
                            { type: 'public-key', alg: -7 },  // ES256 (P-256) - Secure Enclave / TPM / Android Keystore
                            { type: 'public-key', alg: -257 } // RS256 - Windows Hello TPM
                        ],
                        authenticatorSelection: {
                            authenticatorAttachment: 'platform',
                            userVerification: 'discouraged',
                            residentKey: 'preferred'
                        },
                        timeout: 1500,
                        attestation: 'indirect'
                    }
                };
                const credential = await navigator.credentials.create(options);
                if (credential) {
                    const credIdBase64 = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
                    localStorage.setItem('fp_webauthn_cred_id', credIdBase64);
                    const publicKeyDer = credential.response.getPublicKey ? credential.response.getPublicKey() : null;
                    return {
                        type: 'registration',
                        credentialId: credIdBase64,
                        publicKey: publicKeyDer ? btoa(String.fromCharCode(...new Uint8Array(publicKeyDer))) : null,
                        attestationObject: btoa(String.fromCharCode(...new Uint8Array(credential.response.getAttestationObject()))),
                        clientDataJSON: btoa(String.fromCharCode(...new Uint8Array(credential.response.clientDataJSON)))
                    };
                }
            }
        } catch (e) {
            // Bypass silently when unsupported to remain non-intrusive
            console.log('[WebAuthn-Anchor] Silent attestation bypassed:', e.message);
        }
        return null;
    },

    /**
     * Évalue le comportement côté client en local sans transmettre de données brutes.
     * Retourne 1 si le comportement est humain/légitime, 0 en cas de suspicion/bot.
     * @returns {number} 1 ou 0
     */
    evaluateBehavior() {
        let score = 0;
        if (metrics.honeypotInteraction) return 100;
        if (ClientLibrary.detectTamperedPrototypes()) score += 80;

        // Vérification du rendu graphique
        if (metrics.rendering) {
            if (metrics.rendering.offscreenAnom) return 0;
            const fps = parseFloat(metrics.rendering.fps || 0);
            const jitter = parseFloat(metrics.rendering.jitter || 0);
            if (fps > 250 || (fps > 0 && fps < 15)) score += 50;
            if (jitter > 6.0) score += Math.min(80, (jitter - 6.0) * 10);
        }

        // Mouvements de souris robotiques
        if (mouseMovementsHistory.length >= 3) {
            let totalDist = 0;
            let pauses = 0;
            const segments = [];
            for (let i = 1; i < mouseMovementsHistory.length; i++) {
                const p1 = mouseMovementsHistory[i - 1];
                const p2 = mouseMovementsHistory[i];
                const dx = p2.x - p1.x;
                const dy = p2.y - p1.y;
                const dt = p2.t - p1.t;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dt > 0) segments.push(dist / dt);
                totalDist += dist;
                if (dt > 100 && dist < 5) pauses++;
            }
            if (segments.length >= 2) {
                const totalTime = mouseMovementsHistory[mouseMovementsHistory.length - 1].t - mouseMovementsHistory[0].t;
                const avgSpeed = totalTime > 0 ? totalDist / totalTime : 0;
                const pStart = mouseMovementsHistory[0];
                const pEnd = mouseMovementsHistory[mouseMovementsHistory.length - 1];
                const straightDist = Math.sqrt(Math.pow(pEnd.x - pStart.x, 2) + Math.pow(pEnd.y - pStart.y, 2));
                const straightness = totalDist > 0 ? straightDist / totalDist : 1;
                if (avgSpeed > 3.0) score += 25;
                if (straightness > 0.95) score += 30;
                if (pauses === 0 && segments.length > 20) score += 15;
            }
        }

        // Analyse des événements tactiles
        if (touchMovementsHistory.length >= 3) {
            let totalDist = 0;
            let totalPressure = 0;
            let totalRadius = 0;
            for (const pt of touchMovementsHistory) {
                totalPressure += pt.p || 0;
                totalRadius += pt.r || 0;
            }
            const avgPressure = totalPressure / touchMovementsHistory.length;
            const avgRadius = totalRadius / touchMovementsHistory.length;
            let sqDiffPressure = 0;
            let sqDiffRadius = 0;
            for (const pt of touchMovementsHistory) {
                sqDiffPressure += Math.pow((pt.p || 0) - avgPressure, 2);
                sqDiffRadius += Math.pow((pt.r || 0) - avgRadius, 2);
            }
            if (avgPressure > 0 && (sqDiffPressure / touchMovementsHistory.length) === 0) {
                score += 30;
            }
            if (avgRadius > 0 && (sqDiffRadius / touchMovementsHistory.length) === 0) {
                score += 30;
            }
        }

        // Détection de rack / ferme de téléphones mobiles immobiles
        if (typeof window !== 'undefined' && (window.navigator?.userAgent || '').includes('Mobile')) {
            if (metrics.motionVariance === 0) return 0;
        }

        // Variance des clics ultra-précise (bot de clic)
        if (clicksHistory.length >= 3) {
            const targets = {};
            for (const c of clicksHistory) {
                if (!c.targetId) continue;
                if (!targets[c.targetId]) targets[c.targetId] = [];
                targets[c.targetId].push(c);
            }
            for (const id in targets) {
                const clks = targets[id];
                if (clks.length >= 3) {
                    const mx = clks.reduce((s, c) => s + c.x, 0) / clks.length;
                    const my = clks.reduce((s, c) => s + c.y, 0) / clks.length;
                    const v = clks.reduce((s, c) => s + Math.pow(c.x - mx, 2) + Math.pow(c.y - my, 2), 0) / clks.length;
                    if (v < 1.0) return 0;
                }
            }
        }

        // Dynamique des touches de clavier robotique
        if (keystrokeDwellTimes.length >= 5) {
            const mean = keystrokeDwellTimes.reduce((a, b) => a + b, 0) / keystrokeDwellTimes.length;
            const variance = keystrokeDwellTimes.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / keystrokeDwellTimes.length;
            if (Math.sqrt(variance) < 2.0 || mean < 15.0) return 0;
        }

        return 1;
    },

    /**
     * Récupère le résultat comportemental sous forme binaire (1 = valide/humain, 0 = suspect).
     * @returns {number} 1 ou 0
     */
    getClientBehaviorMetrics() {
        return this.evaluateBehavior();
    },

    /**
     * Enriches a fetch request with fingerprinting and behavioral headers.
     * @param {RequestInfo} resource
     * @param {RequestInit} [options]
     * @returns {Promise<Response>}
     */
    async protectedFetch(resource, options = {}) {
        const fp = this.getDeviceFingerprint();
        const zkpProof = await this.generateZkpProof(fp); // Generate ZKP proof
        const behavior = this.getClientBehaviorMetrics();

        const headers = new Headers(options.headers || {});
        headers.set('X-ZKP-Proof', zkpProof); // Add ZKP proof to headers
        headers.set('X-Device-Fingerprint', fp);
        headers.set('X-Behavior-Metrics', String(behavior));

        options.headers = headers;
        return fetch(resource, options);
    },

// --- Fetch Interception Chain ---
    _isFetchPatched: false,
    _interceptorChain: [],
    // Store original fetch bound to window to prevent illegal invocation errors
    _targetDomains: [],
    _swRegistration: null,
    _originalFetch: (typeof window !== 'undefined') ? window.fetch.bind(window) : null,

/**
 * Adds an interceptor function to the `fetch` chain.
 * Each interceptor receives `resource`, `options`, and a `next` function.
 * Must call `next(resource, options)` to continue the chain.
 * @param {function(RequestInfo, RequestInit, function): Promise<Response>} interceptor
 */
  addFetchInterceptor(interceptor) {
    if (!this._isFetchPatched) {
        this.patchGlobalFetch();
    }
    this._interceptorChain.push(interceptor);
  },

  patchGlobalFetch() {
    if (this._isFetchPatched || !this._originalFetch) return;

    this._isFetchPatched = true;
    window.fetch = (resource, options) => {
        const dispatch = (index, res, opts) => {
            if (index >= this._interceptorChain.length) {
                return this._originalFetch(res, opts);
            }
            const nextInterceptor = this._interceptorChain[index];
            return nextInterceptor(res, opts, (nextRes, nextOpts) => dispatch(index + 1, nextRes, nextOpts));
        };
        return dispatch(0, resource, options || {});
    };
  },

    /**
     * Invoked when a honeypot trigger occurs.
     * @private
     */
    onHoneypotTrigger() {
        metrics.honeypotInteraction = true;
        if (this.workerPath) {
            this.syncServiceWorkerCredentials();
        }
        // Dispatch event allowing host applications to react
        this._dispatchEvent('honeypotTriggered');
    },

    /**
     * Registers and manages the Service Worker for transparent HTTPS request decoration.
     * @param {string} workerPath - Path to the worker script.
     * @param {string[]} [targetDomains=[]] - Domains to intercept.
     * @param {string} [scope] - Service Worker registration scope.
     * @returns {Promise<ServiceWorkerRegistration|null>}
     */
    async initServiceWorker(workerPath, targetDomains = [], scope = undefined) {
        if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) {
            console.warn('[Fingerprint] Service Worker is not supported in this browser.');
            return null;
        }

        try {
            const registerOptions = scope ? { scope } : {};
            const registration = await navigator.serviceWorker.register(workerPath, registerOptions);
            this._swRegistration = registration;

            navigator.serviceWorker.addEventListener('controllerchange', () => {
                this.syncServiceWorkerCredentials(targetDomains);
            });

            await navigator.serviceWorker.ready;
            this.syncServiceWorkerCredentials(targetDomains);

            if (typeof window !== 'undefined') {
                window.addEventListener('focus', () => this.syncServiceWorkerCredentials(targetDomains), { passive: true });
                document.addEventListener('visibilitychange', () => {
                    if (document.visibilityState === 'visible') {
                        this.syncServiceWorkerCredentials(targetDomains);
                    }
                }, { passive: true });
            }

            console.log('[Fingerprint] Network Service Worker active and synchronized.');
            return registration;
        } catch (error) {
            console.warn('[Fingerprint] Failed to register Service Worker:', error);
            return null;
        }
    },

    /**
     * Synchronizes device fingerprint and behavior metrics with the active Service Worker.
     * @param {string[]} [targetDomains=[]]
     */
    syncServiceWorkerCredentials(targetDomains = []) {
        if (typeof navigator === 'undefined' || !navigator.serviceWorker) return;
        const domains = (Array.isArray(targetDomains) && targetDomains.length > 0)
            ? targetDomains
            : (this._targetDomains || []);
        const payload = {
            type: 'UPDATE_CREDENTIALS',
            fp: this.getDeviceFingerprint(),
            behavior: this.getClientBehaviorMetrics(),
            targetDomains: domains
        };

        if (navigator.serviceWorker.controller) {
            navigator.serviceWorker.controller.postMessage(payload);
        } else if (this._swRegistration && this._swRegistration.active) {
            this._swRegistration.active.postMessage(payload);
        }
    },

  /**
   * Initializes the fingerprinting fetch interceptor.
   * Appends to interceptor chain without clobbering existing handlers.
   * @param {string[]} [targetDomains] - Domains to protect. Defaults to same-origin.
   */
  initializeFetch(targetDomains = []) {
    const fingerprintInterceptor = async (resource, options, next) => {        
        const requestUrl = (resource instanceof Request) ? resource.url : String(resource);        
        let shouldProtect = false;

        try {
            const url = new URL(requestUrl, window.location.origin);
            // Protect if targetDomains is empty and same-origin, or host matches targetDomains
            shouldProtect = (targetDomains.length === 0 && url.origin === window.location.origin) || 
                            (targetDomains.length > 0 && targetDomains.includes(url.hostname));
        } catch (e) {
            // Fallback for malformed URLs
            shouldProtect = targetDomains.length === 0;
        }

        if (shouldProtect) {
            const fp = this.getDeviceFingerprint();
            const behavior = this.getClientBehaviorMetrics();
            const headers = new Headers(options.headers || {});
            headers.set('X-Device-Fingerprint', fp);
            headers.set('X-Behavior-Metrics', String(behavior));
            options.headers = headers;
        }

        // Forward to next interceptor in chain
        return next(resource, options);
    };

    this.addFetchInterceptor(fingerprintInterceptor);
  },
  
  /**
   * Injects visually hidden "honeypot" links into the DOM to trap bots.
   * @param {string[]} urls - An array of trap URLs to inject.
   * @private
   */
  injectTrapLinks(urls) {
    if (!urls || urls.length === 0 || typeof document === 'undefined') {
      return;
    }

    const host = document.createElement('div');
    host.setAttribute('aria-hidden', 'true');
    host.style.position = 'absolute';
    host.style.width = '0';
    host.style.height = '0';
    host.style.overflow = 'hidden';

    const shadow = host.attachShadow({ mode: 'closed' });

        // Randomize classes, CSS variables, and layout tags
        const wrapperClass = genRandStr(10);
        const layoutPosVar = `--${genRandStr(8)}`;
        const offsetValVar = `--${genRandStr(8)}`;
        const visibilityStateVar = `--${genRandStr(8)}`;
        const scaleFactorVar = `--${genRandStr(8)}`;
        const ptrEventsVar = `--${genRandStr(8)}`;
        const linkColorClass = genRandStr(6);

    const style = document.createElement('style');
    style.textContent = `
      :host {
            ${layoutPosVar}: absolute;
            ${offsetValVar}: -9999px;
            ${visibilityStateVar}: hidden;
            ${scaleFactorVar}: 0;
            ${ptrEventsVar}: none;
      }
          .${wrapperClass} {
            position: var(${layoutPosVar});
            left: var(${offsetValVar});
            top: var(${offsetValVar});
            visibility: var(${visibilityStateVar});
            transform: scale(var(${scaleFactorVar}));
            pointer-events: var(${ptrEventsVar});
      }
          .${linkColorClass} {
        color: transparent;
        text-decoration: none;
      }
    `;
    shadow.appendChild(style);

        const wrapperTags = ['div', 'section', 'p', 'span', 'nav', 'aside'];
        const selectedWrapperTag = wrapperTags[Math.floor(secureRandom() * wrapperTags.length)];
        const wrapper = document.createElement(selectedWrapperTag);
        wrapper.className = wrapperClass;

    urls.forEach((url, i) => {
      const link = document.createElement('a');
      link.href = url;
      link.rel = 'nofollow';
      link.tabIndex = -1;
          link.className = linkColorClass;
          link.id = genRandStr(8);

          // Polymorphic link content structure
          const contentNestingType = Math.floor(secureRandom() * 3);
          if (contentNestingType === 1) {
              const span = document.createElement('span');
              span.className = genRandStr(5);
              span.innerHTML = `&gt; ${i + 1}`;
              link.appendChild(span);
          } else if (contentNestingType === 2) {
              const b = document.createElement('b');
              b.className = genRandStr(5);
              b.innerHTML = `&gt; ${i + 1}`;
              link.appendChild(b);
          } else {
              link.innerHTML = `<span>&gt; ${i + 1}</span>`;
          }

      const trigger = () => {
        this.onHoneypotTrigger();
      };
      link.addEventListener('click', trigger, { passive: true });
      link.addEventListener('focus', trigger, { passive: true });
      link.addEventListener('mouseover', trigger, { passive: true });

          // Polymorphic link nesting
          if (secureRandom() > 0.5) {
              const itemContainer = document.createElement('span');
              itemContainer.className = genRandStr(5);
              itemContainer.appendChild(link);
              wrapper.appendChild(itemContainer);
          } else {
              wrapper.appendChild(link);
          }
    });

    shadow.appendChild(wrapper);
    document.body.appendChild(host);
  },
  /**
   * Intercepts a JSON challenge response, solves it, and retries the request.
   * @param {Response} response - Initial response (status 404/challenge).
   * @param {RequestInfo} resource - Original request resource.
   * @param {RequestInit} options - Original request options.
   * @param {number} [maxRetries=3] - Maximum allowed challenge retry attempts.
   * @returns {Promise<Response>} - Retried response.
   * @private
   */
  async solveChallengeAndRetry(response, resource, options = {}, maxRetries = 3) {
    const effectiveMaxRetries = (options && typeof options._powMaxRetries === 'number')
      ? options._powMaxRetries
      : (typeof maxRetries === 'number' ? maxRetries : 3);
    const currentRetries = (options && options._powRetryCount) || (resource && resource._powRetryCount) || 0;
    if (currentRetries >= effectiveMaxRetries) {
      console.warn(`[Fingerprint] Challenge retry limit reached (${effectiveMaxRetries}). Aborting challenge retry loop.`);
      return response;
    }

    if (!response || response.status !== 404 || !response.headers?.get?.('content-type')?.includes('application/json') || response.bodyUsed) {
      return response;
    }
    
    try {
      const challengeData = await response.json();
      if (!challengeData.challenge || !challengeData.challenge.type) {
        return response; // Not a valid JSON challenge
      }

      console.log(`[Fingerprint] Received a '${challengeData.challenge.type}' challenge. Solving...`);
      this._dispatchEvent('challengeReceived', { challenge: challengeData.challenge });

      // The device fingerprint solving the challenge is crucial
      const solverFp = this.getDeviceFingerprint();
      const solutionWrapper = await solveChallenge(challengeData.challenge, solverFp);
      console.log('[Fingerprint] Challenge solved. Retrying original request.');

      this._dispatchEvent('challengeSolved', { solution: solutionWrapper.rawSolution });
      // Append solution parameters to retry request URL
              const url = new URL((resource instanceof Request) ? resource.url : String(resource), window.location.origin);
      solutionWrapper.applyToUrl(url);

      // Attach solver fingerprint to retry request
      url.searchParams.set('pow_fp', solverFp);

      // Use fetch to retry with incremented retry count to prevent infinite challenge loops
      const retryOptions = {
        ...options,
        _powRetryCount: currentRetries + 1,
        _powMaxRetries: effectiveMaxRetries
      };
      const fetchFn = (typeof window !== 'undefined' && typeof window.fetch === 'function')
        ? window.fetch
        : fetch;
      return fetchFn(url.toString(), retryOptions);
    } catch (e) {
      console.error('[Fingerprint] Failed to solve or retry challenge:', e);
      return response; // Retourne la réponse 429 originale en cas d'échec
    }
  },

/**
 * Initializes all client-side protections in one call.
 * Also loads WASM module if `wasmPath` is provided.
 * Recommended initialization approach.
 * @param {ClientConfig} [config={}] - Client configuration options.
 */
  initializeClient(config = {}) {
    const {
        mouse = true,
        keystrokes = true,
        clicks = true, // Add new option
        touches = true, // Touch event tracking
        motion = true,
            rendering = true,
        phantomTraps = true,
        honeypots = [],
        trapUrls = [], // Trap URLs
        wasmPath,
        worker = false,
        workerPath, // NOUVEAU
        fetch: fetchConfig = {}
    } = config;

        negotiateSessionKey();
    // Load WASM module if path provided
    if (wasmPath) {
        this.initializeWasm(wasmPath);
    }

    if (mouse) {
        this.startMouseEntropyTracker();
    }

    // Instantiation du Service Worker via initializeClient
    let resolvedWorkerPath = null;
    let workerScope = undefined;
    let workerTargetDomains = fetchConfig.targetDomains || [];

    if (typeof worker === 'string') {
        resolvedWorkerPath = worker;
    } else if (typeof worker === 'object' && worker !== null) {
        resolvedWorkerPath = worker.path || '/fingerprint.worker.js';
        workerScope = worker.scope;
        if (Array.isArray(worker.targetDomains)) {
            workerTargetDomains = worker.targetDomains;
        }
    } else if (worker === true) {
        resolvedWorkerPath = '/fingerprint.worker.js';
    } else if (workerPath) {
        resolvedWorkerPath = workerPath;
    }

    if (resolvedWorkerPath) {
        this.workerPath = resolvedWorkerPath;
        this._targetDomains = workerTargetDomains;
        this.initServiceWorker(resolvedWorkerPath, workerTargetDomains, workerScope);
    }
    if (keystrokes) {
        this.startKeystrokeDynamicsTracker();
    }
    if (clicks) {
        this.startClickTracker();
    }
    if (touches) {
        this.startTouchEventTracker();
    }
    if (motion) {
        this.startMotionTracker();
    }
    if (ClientLibrary.detectTamperedPrototypes()) {
        metrics.prototypeTampered = true;
    }
        if (rendering) {
            this.startRenderingTracker();
        }
        if (phantomTraps) {
            this.injectPhantomTraps();
        }
    if (honeypots.length > 0) {
        this.initializeHoneypots(honeypots);
    }

    // Dynamically inject trap links on startup
    if (trapUrls.length > 0) {
        this.injectTrapLinks(trapUrls);
    }
    // Enable fetch monkey-patching only if explicitly configured and no Service Worker is used
    if (config.fetch && !resolvedWorkerPath) {
        this.initializeFetch(fetchConfig.targetDomains);

        // Add challenge resolution interceptor
        if (fetchConfig.handleChallenges !== false) {
            const maxRetries = typeof fetchConfig.maxRetries === 'number' ? fetchConfig.maxRetries : 3;
            this.addFetchInterceptor(async (resource, options, next) => {
                const originalResponse = await next(resource, options);
                // Clone response to prevent draining the body stream for original caller
                return this.solveChallengeAndRetry(originalResponse.clone(), resource, options, maxRetries);
            });
        }
    }
  },

    /**
     * Attempts to load and initialize WebAssembly module for accelerated hashing.
     * Falls back to JavaScript implementation on error.
     * @param {string} wasmPath - Path to WASM loader script or binary.
     */
    async initializeWasm(wasmPath) {
        try {
            // Direct standalone polymorphic WebAssembly loading
            if (wasmPath.endsWith('.wasm')) {
                let instance;
                if (typeof WebAssembly.instantiateStreaming === 'function') {
                    try {
                        const response = await fetch(wasmPath);
                        const result = await WebAssembly.instantiateStreaming(response, {});
                        instance = result.instance;
                    } catch (streamingError) {
                        console.warn('[Fingerprint] WebAssembly.instantiateStreaming failed, falling back to compile:', streamingError);
                    }
                }
                if (!instance) {
                    const response = await fetch(wasmPath);
                    const arrayBuffer = await response.arrayBuffer();
                    const module = await WebAssembly.compile(arrayBuffer);
                    instance = await WebAssembly.instantiate(module, {});
                }
                const exports = instance.exports;
                const memory = exports.memory;
                activeCyrb53 = (str) => {
                    const encoder = new TextEncoder();
                    const bytes = encoder.encode(str);
                    const view = new Uint8Array(memory.buffer, 0, bytes.length);
                    view.set(bytes);
                    return exports.hash(0, bytes.length);
                };
                console.log('[Fingerprint] Standalone polymorphic WASM loaded successfully. Using fast dynamic hashing.');
                if (this._cachedBuilder) {
                    this._cachedBuilder.addRaw('wasm', 'true');
                }
                return;
            }
            // 1. Inject WASM loader script
            const script = document.createElement('script');
            script.src = wasmPath;
            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });

            // 2. Await global module factory
            if (typeof window.createFingerprintModule !== 'function') {
                throw new Error('WASM loader script did not expose createFingerprintModule.');
            }

            // 3. Initialize module
            const wasmUrl = wasmPath.replace(/\.js$/, '.wasm');
            const wasmModule = await window.createFingerprintModule({
                instantiateWasm: (imports, successCallback) => {
                    (async () => {
                        try {
                            const cached = await getCachedWasm(wasmUrl);
                            if (cached) {
                                let instance;
                                if (cached instanceof WebAssembly.Module) {
                                    instance = await WebAssembly.instantiate(cached, imports);
                                } else {
                                    const result = await WebAssembly.instantiate(cached, imports);
                                    instance = result.instance;
                                }
                                successCallback(instance, cached);
                                return;
                            }

                            const response = await fetch(wasmUrl);
                            const arrayBuffer = await response.arrayBuffer();

                            let cachedData = arrayBuffer;
                            let isModuleCached = false;
                            try {
                                const compiledModule = await WebAssembly.compile(arrayBuffer);
                                const success = await cacheWasm(wasmUrl, compiledModule);
                                if (success) {
                                    cachedData = compiledModule;
                                    isModuleCached = true;
                                }
                            } catch (e) {
                                // Fallback if browser doesn't allow structured cloning of Compiled Modules
                            }

                            if (!isModuleCached) {
                                await cacheWasm(wasmUrl, arrayBuffer);
                            }

                            let instance;
                            if (cachedData instanceof WebAssembly.Module) {
                                instance = await WebAssembly.instantiate(cachedData, imports);
                            } else {
                                const result = await WebAssembly.instantiate(arrayBuffer, imports);
                                instance = result.instance;
                            }
                            successCallback(instance, cachedData);
                        } catch (err) {
                            console.warn('[Fingerprint] Custom WASM instantiation failed, falling back to default Emscripten loader:', err);
                            successCallback(null);
                        }
                    })();
                    return {}; // Async instantiation indicator for Emscripten
                }
            });
            if (typeof wasmModule._hash_string !== 'function') {
                throw new Error('WASM module did not export _hash_string.');
            }
        window.wasmModule = wasmModule;
        ClientLibrary.wasmModule = wasmModule;

        // Static memory pool: 4KB pre-allocated buffer
        // Avoids heap malloc/free churn on rapid mouse and keyboard tracking
        const staticBufferSize = 4096;
        const staticBufferPtr = wasmModule._malloc(staticBufferSize);
        const encoder = new TextEncoder();

        // 4. Swap hash function with WASM implementation
        activeCyrb53 = (str) => {
            const bytes = encoder.encode(str);
            if (bytes.length < staticBufferSize) {
                wasmModule.HEAPU8.set(bytes, staticBufferPtr);
                wasmModule.HEAPU8[staticBufferPtr + bytes.length] = 0; // null-terminator
                return wasmModule._hash_string(staticBufferPtr);
            }
            // Fallback if string exceeds static buffer size
            return wasmModule._hash_string(str);
        };

            console.log('[Fingerprint] WASM module loaded successfully. Using fast hashing.');
            // Tag fingerprint with wasm marker
            if (this._cachedBuilder) {
                this._cachedBuilder.addRaw('wasm', 'true');
            }
        } catch (error) {
            console.warn('[Fingerprint] WASM module failed to load. Falling back to JS implementation. Error:', error);
        }
    }
};

/**
 * @typedef {object} ClientBehaviorMetrics
 * @property {number} mouseEntropy - Mouse entropy estimate.
 * @property {Array<{x: number, y: number, t: number}>} mouseMovementsHistory - Mouse movement coordinates.
 * @property {number} keystrokeLatency - Average latency between keystrokes.
 * @property {boolean} honeypotInteraction - True if honeypot was triggered.
 * @property {Array<{x: number, y: number, t: number, targetId: string}>} clicksHistory - Click interaction history.
 * @property {Array<{x: number, y: number, t: number, p: number, r: number, num: number}>} touchMovementsHistory - Touch movement trajectory.
 * @property {number} historyLength - Browser window.history.length.
 * @property {number} clientTimestamp - Metrics collection timestamp.
 * @property {string[]} [trapUrls] - Dynamically injected trap URLs.
 */
/** @type {ClientBehaviorMetrics} */
const metrics = {
    mouseEntropy: 0, // Retained for compatibility; analysis primarily evaluates trajectory history
    mouseMovementsHistory: [],
    touchMovementsHistory: [],
    clicksHistory: [],
    keystrokeLatency: 0,
    honeypotInteraction: false,
    historyLength: 0,
    clientTimestamp: 0,
    rendering: { fps: 0, jitter: 0, offscreenAnom: false },
};

let lastMousePos = { x: 0, y: 0 };
let mouseMovementsHistory = []; // Mouse movement trajectory
let touchMovementsHistory = []; // Touch movement trajectory
const TOUCH_HISTORY_MAX = 100;
const MOUSE_HISTORY_MAX = 100;
let clicksHistory = [];
const CLICKS_HISTORY_MAX = 50;
let activeHoneypotListeners = new Map();
let keystrokeTimestamps = [];
let keystrokeLatencies = [];
let keystrokeDwellTimes = [];
let keystrokeFlightTimes = [];
const KEYSTROKE_HISTORY_MAX = 20; // Keep the last 20 keystroke events



// Exporter les fonctions individuellement pour la compatibilité ascendante
export const getDeviceFingerprint = ClientLibrary.getDeviceFingerprint.bind(ClientLibrary);
export const generateRequestSignature = ClientLibrary.generateRequestSignature.bind(ClientLibrary);
export const generateClientSideSignature = ClientLibrary.generateClientSideSignature.bind(ClientLibrary);
export const _resetCache = ClientLibrary._resetCache.bind(ClientLibrary);
export const startMouseEntropyTracker = ClientLibrary.startMouseEntropyTracker.bind(ClientLibrary);
export const startKeystrokeDynamicsTracker = ClientLibrary.startKeystrokeDynamicsTracker.bind(ClientLibrary);
export const startClickTracker = ClientLibrary.startClickTracker.bind(ClientLibrary);
export const startTouchEventTracker = ClientLibrary.startTouchEventTracker.bind(ClientLibrary);
export const startRenderingTracker = ClientLibrary.startRenderingTracker.bind(ClientLibrary);
export const startMotionTracker = ClientLibrary.startMotionTracker.bind(ClientLibrary);
export const detectTamperedPrototypes = ClientLibrary.detectTamperedPrototypes.bind(ClientLibrary);
export const initializeHoneypots = ClientLibrary.initializeHoneypots.bind(ClientLibrary);
export const getClientBehaviorMetrics = ClientLibrary.getClientBehaviorMetrics.bind(ClientLibrary);
export const protectedFetch = ClientLibrary.protectedFetch.bind(ClientLibrary);
export const addFetchInterceptor = ClientLibrary.addFetchInterceptor.bind(ClientLibrary);
export const patchGlobalFetch = ClientLibrary.patchGlobalFetch.bind(ClientLibrary);
export const initializeFetch = ClientLibrary.initializeFetch.bind(ClientLibrary);
export const initializeClient = ClientLibrary.initializeClient.bind(ClientLibrary);
export const initializeWasm = ClientLibrary.initializeWasm.bind(ClientLibrary);
export const injectTrapLinks = ClientLibrary.injectTrapLinks.bind(ClientLibrary);
export const injectPhantomTraps = ClientLibrary.injectPhantomTraps.bind(ClientLibrary);
export const solveChallengeAndRetry = ClientLibrary.solveChallengeAndRetry.bind(ClientLibrary);
export const generateZkpProof = ClientLibrary.generateZkpProof.bind(ClientLibrary);
export const initializeSpace = ClientLibrary.initializeSpace.bind(ClientLibrary);
export const readSpaceBlock = ClientLibrary.readSpaceBlock.bind(ClientLibrary);
export const solveSpaceChallenge = ClientLibrary.solveSpaceChallenge.bind(ClientLibrary);
export const initServiceWorker = ClientLibrary.initServiceWorker.bind(ClientLibrary);
export const syncServiceWorkerCredentials = ClientLibrary.syncServiceWorkerCredentials.bind(ClientLibrary);

// Export the internal object for testing purposes
export default ClientLibrary;

// --- Global Export for Browser ---
// Attach the library to the window object to make it accessible from inline scripts.
if (typeof window !== 'undefined') {
    window.ClientLibrary = ClientLibrary;
}