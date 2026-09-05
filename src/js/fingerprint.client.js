import {cyrb53 as jsCyrb53, FingerprintBuilder} from './fingerprint.builder.js';
import {solveChallenge} from './pow.solver.js';

// Variable pour stocker la fonction de hachage active.
// Par défaut, c'est l'implémentation JavaScript.
let activeCyrb53 = jsCyrb53;

const ClientLibrary = {
    // Cache pour éviter de recalculer les constantes (Hardware, etc.)
    _cachedBuilder: null,
    /**
     * @private
     * Dispatches a custom event from the window object.
     * @param {string} eventName - The name of the event.
     * @param {object} [detail={}] - The data to include in the event's detail property.
     */
    _dispatchEvent(eventName, detail = {}) {
        if (typeof window === 'undefined' || typeof CustomEvent === 'undefined') return;
        const event = new CustomEvent(`fingerprint:${eventName}`, { detail });
        window.dispatchEvent(event);
    },

    /**
     * Wrapper interne pour la fonction de hachage.
     * @private
     */
    _hasher: (str, seed) => activeCyrb53(str, seed),

    /**
     * Génère l'empreinte de l'appareil actuel.
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

            // 1. Hardware (Très stable) : Cœurs, RAM, GPU (si dispo via canvas), Touch
            this._cachedBuilder.add(
                "hw", // Utilise maintenant le hasher actif
                `${nav.hardwareConcurrency}_${nav.deviceMemory}_${nav.maxTouchPoints}`,
            );

            // 2. Geo/Locale (Stable sauf voyage/VPN) : Timezone, Langue
            this._cachedBuilder.add(
                "geo",
                `${Intl.DateTimeFormat().resolvedOptions().timeZone}_${nav.language}_${new Date().getTimezoneOffset()}`,
            );

            // 3. Screen (Stable sauf changement moniteur/zoom) : Dimensions, ColorDepth
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
                    canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
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

            // 7. Détection des artefacts du Chrome DevTools Protocol (CDP)
            // Ces variables sont souvent injectées par les outils d'automatisation.
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

            // 7. Bot Detection (Indication cachée)
            if (nav.webdriver) this._cachedBuilder.add("bot", "true");
        }

        return this._cachedBuilder.toString();
    },

    /**
     * Génère une signature de requête incluant le contexte.
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
     * Génère une signature HMAC-SHA256 en utilisant l'API Web Crypto.
     * @param {object} payload - Les données à signer.
     * @param {string} secret - La clé secrète partagée.
     * @returns {Promise<string>} La signature hexadécimale.
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
        // Réinitialise le hasher à l'implémentation JS par défaut.
        activeCyrb53 = jsCyrb53;
        this._cachedBuilder = null;
    },

    /**
     * Démarre le suivi des mouvements de la souris pour calculer l'entropie.
     * À appeler une fois sur la page.
     */
    startMouseEntropyTracker() {
        // Utiliser un drapeau pour éviter d'attacher l'écouteur plusieurs fois
        if (this._mouseTrackerAttached) return;
        this._mouseTrackerAttached = true;
 
        document.addEventListener('mousemove', (e) => {
            // NOUVEAU: Capturer une série de points {x, y, t}
            if (mouseMovementsHistory.length >= MOUSE_HISTORY_MAX) {
                // Garder la taille de l'historique constante pour éviter une consommation mémoire excessive.
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
     * Démarre le suivi de la dynamique de frappe pour calculer la latence.
     * À appeler une fois sur la page.
     */
    startKeystrokeDynamicsTracker() {
        // S'assurer de ne pas attacher l'écouteur plusieurs fois
        if (keystrokeTimestamps.length > 0) return;

        document.addEventListener('keydown', () => {
            const now = performance.now();
            if (keystrokeTimestamps.length > 0) {
                const lastTimestamp = keystrokeTimestamps[keystrokeTimestamps.length - 1];
                const latency = now - lastTimestamp;
                // On ignore les latences irréalistes (trop longues ou trop courtes)
                if (latency > 10 && latency < 2000) { // Augmenté à 2s
                    if (keystrokeLatencies.length >= KEYSTROKE_HISTORY_MAX) {
                        keystrokeLatencies.shift(); // Garder la taille de l'historique
                    }
                    keystrokeLatencies.push(latency);
                }
            }
            keystrokeTimestamps.push(now);
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
     * Initialise ou réinitialise les honeypots côté client pour une détection immédiate.
     * Les anciens écouteurs sont supprimés avant d'en ajouter de nouveaux.
     * @param {string[]} honeypotFieldNames - Noms des champs de formulaire cachés.
     */
    initializeHoneypots(honeypotFieldNames) {
        // 1. Nettoyer les anciens écouteurs
        activeHoneypotListeners.forEach((listener, field) => {
            field.removeEventListener('input', listener);
        });
        activeHoneypotListeners.clear();

        // 2. Ajouter les nouveaux écouteurs
        honeypotFieldNames.forEach(fieldName => {
            const field = document.querySelector(`[name="${fieldName}"]`);
            if (field) {
                // On utilise une fonction nommée (ou une référence) pour pouvoir la supprimer plus tard.
                // L'option { once: true } est excellente, mais pour une réinitialisation complète,
                // il est plus propre de gérer le nettoyage nous-mêmes.
                const listener = () => {
                    this.onHoneypotTrigger();
                    // Se supprime lui-même après exécution, comme { once: true }
                    field.removeEventListener('input', listener);
                };
                field.addEventListener('input', listener);
                activeHoneypotListeners.set(field, listener); // On stocke la référence
            }
        });
    },

    /**
     * Récupère les métriques comportementales collectées.
     * À appeler avant d'envoyer une requête sensible.
     * @returns {ClientBehaviorMetrics}
     */
    getClientBehaviorMetrics() {
        // Add history length as a behavioral signal.
        metrics.historyLength = window.history.length;

        // Ajoute un timestamp au moment de la collecte pour la détection de rejeu.
        metrics.clicksHistory = clicksHistory;
        metrics.clientTimestamp = Date.now();

        // NOUVEAU: Inclure l'historique des mouvements de la souris pour une analyse côté serveur.
        metrics.mouseMovementsHistory = mouseMovementsHistory;

        // Calcule la latence moyenne des frappes
        if (keystrokeLatencies.length > 0) {
            const sum = keystrokeLatencies.reduce((a, b) => a + b, 0);
            metrics.keystrokeLatency = sum / keystrokeLatencies.length;
        } else {
            metrics.keystrokeLatency = 0;
        }
        return metrics;
    },

    /**
     * Enrichit une requête fetch avec les en-têtes de fingerprinting et de comportement.
     * @param {RequestInfo} resource
     * @param {RequestInit} [options]
     * @returns {Promise<Response>}
     */
    async protectedFetch(resource, options = {}) {
        const fp = this.getDeviceFingerprint();
        const behavior = this.getClientBehaviorMetrics();

        const headers = new Headers(options.headers || {});
        headers.set('X-Device-Fingerprint', fp);
        headers.set('X-Behavior-Metrics', JSON.stringify(behavior));

        options.headers = headers;
        return fetch(resource, options);
    },

// --- Système d'interception de Fetch robuste et anti-conflit ---

    _isFetchPatched: false,
    _interceptorChain: [],
    // On stocke la fonction fetch originale et on la lie à son contexte (window)
    // pour éviter les erreurs "Illegal invocation" si une autre lib la modifie.
    _originalFetch: (typeof window !== 'undefined') ? window.fetch.bind(window) : null,

/**
 * Adds an interceptor function to the `fetch` chain.
 * Chaque intercepteur reçoit `resource`, `options`, et une fonction `next`.
 * Il DOIT appeler `next(resource, options)` pour continuer la chaîne.
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
        // Le "dispatcher" qui exécute la chaîne.
        const dispatch = (index, res, opts) => {
            if (index >= this._interceptorChain.length) {
                // Fin de la chaîne, on appelle le fetch original.
                return this._originalFetch(res, opts);
            }
            const nextInterceptor = this._interceptorChain[index];
            // Appelle l'intercepteur actuel en lui passant la fonction pour appeler le suivant.
            return nextInterceptor(res, opts, (nextRes, nextOpts) => dispatch(index + 1, nextRes, nextOpts));
        };
        return dispatch(0, resource, options || {});
    };
  },

    /**
     * La fonction qui est appelée lorsqu'un honeypot est déclenché.
     * @private
     */
    onHoneypotTrigger() {
        metrics.honeypotInteraction = true;
        // Émettre un événement pour que l'application puisse réagir.
        this._dispatchEvent('honeypotTriggered');
    },

  /**
   * Initialise l'intercepteur de fingerprinting.
   * Il s'ajoute à la chaîne d'interception sans écraser les autres.
   * @param {string[]} [targetDomains] - Optionnel. Liste de domaines à protéger.
   * Si non fourni, protège les requêtes de même origine.
   */
  initializeFetch(targetDomains = []) {
    const fingerprintInterceptor = (resource, options, next) => {        
        const requestUrl = (resource instanceof Request) ? resource.url : String(resource);        
        let shouldProtect = false;

        try {
            const url = new URL(requestUrl, window.location.origin);
            // Protéger si la liste de domaines est vide ET que la requête est de même origine,
            // OU si le domaine de la requête est dans la liste fournie.
            shouldProtect = (targetDomains.length === 0 && url.origin === window.location.origin) || 
                            (targetDomains.length > 0 && targetDomains.includes(url.hostname));
        } catch (e) {
            // Si l'URL est relative (ex: '/api/data'), new URL() ne lèvera pas d'erreur.
            // Ce bloc est une sécurité pour les cas où l'URL serait malformée.
            // On protège par défaut si aucune liste de domaines n'est spécifiée.
            shouldProtect = targetDomains.length === 0;
        }

        if (shouldProtect) {
            const fp = this.getDeviceFingerprint();
            const behavior = this.getClientBehaviorMetrics();
            const headers = new Headers(options.headers || {});
            headers.set('X-Device-Fingerprint', fp);
            headers.set('X-Behavior-Metrics', JSON.stringify(behavior));
            options.headers = headers;
        }

        // Passe la main à l'intercepteur suivant dans la chaîne.
        return next(resource, options);
    };

    this.addFetchInterceptor(fingerprintInterceptor);
  }, // <-- VIRGULE AJOUTÉE ICI
  
  /**
   * Injects visually hidden "honeypot" links into the DOM to trap bots.
   * @param {string[]} urls - An array of trap URLs to inject.
   * @private
   */
  injectTrapLinks(urls) {
    if (!urls || urls.length === 0 || typeof document === 'undefined') {
      return;
    }

    const trapContainer = document.createElement('div');
    trapContainer.setAttribute('aria-hidden', 'true');
    trapContainer.style.position = 'absolute';
    trapContainer.style.left = '-9999px';
    trapContainer.style.top = '-9999px';

    urls.forEach(url => {
      const link = document.createElement('a');
      link.href = url;
      link.tabIndex = -1; // Make it unfocusable
      link.textContent = 'config'; // Some plausible text
      trapContainer.appendChild(link);
    });

    document.body.appendChild(trapContainer);
  },
  /**
   * Intercepte une réponse de challenge JSON, le résout, et réessaie la requête.
   * @param {Response} response - La réponse initiale (potentiellement 429).
   * @param {RequestInfo} resource - La ressource de la requête originale.
   * @param {RequestInit} options - Les options de la requête originale.
   * @returns {Promise<Response>} - La réponse de la requête réessayée.
   * @private
   */
  async solveChallengeAndRetry(response, resource, options) {
    if (response.status !== 404 || !response.headers.get('content-type')?.includes('application/json') || response.bodyUsed) {
      return response;
    }
    
    try {
      const challengeData = await response.json();
      if (!challengeData.challenge || !challengeData.challenge.type) {
        return response; // Pas un challenge JSON valide
      }

      console.log(`[Fingerprint] Received a '${challengeData.challenge.type}' challenge. Solving...`);
      this._dispatchEvent('challengeReceived', { challenge: challengeData.challenge });

      // L'empreinte de l'appareil qui résout le challenge est cruciale.
      const solverFp = this.getDeviceFingerprint();
      const solutionWrapper = await solveChallenge(challengeData.challenge, solverFp);
      console.log('[Fingerprint] Challenge solved. Retrying original request.');

      this._dispatchEvent('challengeSolved', { solution: solutionWrapper.rawSolution });
      // Ajouter la solution aux paramètres de la requête pour le nouvel essai
      const url = new URL((resource instanceof Request) ? resource.url : String(resource), window.location.origin);
      // La logique de formatage est maintenant cachée dans la classe ChallengeSolution.
      solutionWrapper.applyToUrl(url);

      // On ajoute l'empreinte du solveur à la requête de réessai.
      url.searchParams.set('pow_fp', solverFp);

      // On utilise la chaîne d'intercepteurs pour la requête réessayée,
      // ce qui garantit que le fetch original est appelé avec le bon contexte.
      // Cela évite de réintroduire l'erreur "Illegal invocation".
      return window.fetch(url.toString(), options);
    } catch (e) {
      console.error('[Fingerprint] Failed to solve or retry challenge:', e);
      return response; // Retourne la réponse 429 originale en cas d'échec
    }
  }, // <-- VIRGULE AJOUTÉE ICI

/**
 * Initialise toutes les protections côté client en une seule fois.
 * Tente également de charger le module WASM si `wasmPath` est fourni.
 * C'est la méthode d'initialisation recommandée.
 * @param {ClientConfig} [config={}] - L'objet de configuration.
 */
  initializeClient(config = {}) {
    const {
        mouse = true,
        keystrokes = true,
        clicks = true, // Add new option
        honeypots = [],
        trapUrls = [], // Nouveau paramètre pour les URL pièges
        wasmPath, // Nouveau paramètre
        fetch: fetchConfig = {}
    } = config;

    // Tentative de chargement du WASM si le chemin est fourni
    if (wasmPath) {
        this.initializeWasm(wasmPath);
    }

    if (mouse) {
        this.startMouseEntropyTracker();
    }
    if (keystrokes) {
        this.startKeystrokeDynamicsTracker();
    }
    if (clicks) {
        this.startClickTracker();
    }
    if (honeypots.length > 0) {
        this.initializeHoneypots(honeypots);
    }

    // Injection dynamique des liens pièges au démarrage
    if (trapUrls.length > 0) {
        this.injectTrapLinks(trapUrls);
    }
    // On active l'interception si `fetch` est configuré, même avec un objet vide.
    if (config.fetch) {
        this.initializeFetch(fetchConfig.targetDomains);

        // Ajoute l'intercepteur pour la résolution de challenge
        if (fetchConfig.handleChallenges !== false) {
            this.addFetchInterceptor(async (resource, options, next) => {
                const originalResponse = await next(resource, options);
                // On clone la réponse pour que la lecture du corps par solveChallengeAndRetry ne la consomme pas pour l'appelant original.
                return this.solveChallengeAndRetry(originalResponse.clone(), resource, options);
            });
        }
    }
  },

    /**
     * Tente de charger et d'initialiser le module WebAssembly pour un hachage plus rapide.
     * Si le chargement échoue, il se rabat silencieusement sur l'implémentation JS.
     * @param {string} wasmPath - Le chemin vers le script de chargement du module WASM (ex: '/fp.js').
     */
    async initializeWasm(wasmPath) {
        try {
            // 1. Injecter le script qui charge le module WASM
            const script = document.createElement('script');
            script.src = wasmPath;
            await new Promise((resolve, reject) => {
                script.onload = resolve;
                script.onerror = reject;
                document.head.appendChild(script);
            });

            // 2. Attendre que la fonction globale `createFingerprintModule` soit disponible
            if (typeof window.createFingerprintModule !== 'function') {
                throw new Error('WASM loader script did not expose createFingerprintModule.');
            }

            // 3. Initialiser le module
            const wasmModule = await window.createFingerprintModule();
            if (typeof wasmModule._hash_string !== 'function') {
                throw new Error('WASM module did not export _hash_string.');
            }
        window.wasmModule = wasmModule;
        ClientLibrary.wasmModule = wasmModule;

            // 4. Remplacer la fonction de hachage par la version WASM
            activeCyrb53 = (str) => {
                // La fonction C++ attend un pointeur, Emscripten gère la conversion
                return wasmModule._hash_string(str);
            };

            console.log('[Fingerprint] WASM module loaded successfully. Using fast hashing.');
            // NOUVEAU: Ajoute un indicateur à l'empreinte pour que le serveur sache que le WASM est actif.
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
 * @property {number} mouseEntropy - Entropie des mouvements de la souris.
 * @property {Array<{x: number, y: number, t: number}>} mouseMovementsHistory - Historique des points de la souris.
 * @property {number} keystrokeLatency - Latence moyenne entre les frappes.
 * @property {boolean} honeypotInteraction - Vrai si un honeypot a été touché.
 * @property {Array<{x: number, y: number, t: number, targetId: string}>} clicksHistory - Historique des clics.
 * @property {number} historyLength - La longueur de l'historique de session du navigateur (`window.history.length`).
 * @property {number} clientTimestamp - Timestamp (Date.now()) de la collecte des métriques.
 * @property {string[]} [trapUrls] - URLs pièges à injecter dynamiquement.
 */
/** @type {ClientBehaviorMetrics} */
const metrics = {
    mouseEntropy: 0, // Conservé pour la compatibilité, mais l'analyse se fait maintenant sur l'historique
    mouseMovementsHistory: [],
    clicksHistory: [],
    keystrokeLatency: 0,
    honeypotInteraction: false,
    historyLength: 0,
    clientTimestamp: 0,
};

let lastMousePos = { x: 0, y: 0 };
let mouseMovementsHistory = []; // NOUVEAU: Historique des points de la souris
const MOUSE_HISTORY_MAX = 100; // Limite le nombre de points stockés
let clicksHistory = [];
const CLICKS_HISTORY_MAX = 50;
let activeHoneypotListeners = new Map(); // Garde une trace des écouteurs actifs
let keystrokeTimestamps = [];
let keystrokeLatencies = []; // NOUVEAU: Tableau dédié pour les latences
const KEYSTROKE_HISTORY_MAX = 20; // On garde l'historique des 20 dernières frappes



// Exporter les fonctions individuellement pour la compatibilité ascendante
export const getDeviceFingerprint = ClientLibrary.getDeviceFingerprint.bind(ClientLibrary);
export const generateRequestSignature = ClientLibrary.generateRequestSignature.bind(ClientLibrary);
export const generateClientSideSignature = ClientLibrary.generateClientSideSignature.bind(ClientLibrary);
export const _resetCache = ClientLibrary._resetCache.bind(ClientLibrary);
export const startMouseEntropyTracker = ClientLibrary.startMouseEntropyTracker.bind(ClientLibrary);
export const startKeystrokeDynamicsTracker = ClientLibrary.startKeystrokeDynamicsTracker.bind(ClientLibrary);
export const startClickTracker = ClientLibrary.startClickTracker.bind(ClientLibrary);
export const initializeHoneypots = ClientLibrary.initializeHoneypots.bind(ClientLibrary);
export const getClientBehaviorMetrics = ClientLibrary.getClientBehaviorMetrics.bind(ClientLibrary);
export const protectedFetch = ClientLibrary.protectedFetch.bind(ClientLibrary);
export const addFetchInterceptor = ClientLibrary.addFetchInterceptor.bind(ClientLibrary);
export const patchGlobalFetch = ClientLibrary.patchGlobalFetch.bind(ClientLibrary);
export const initializeFetch = ClientLibrary.initializeFetch.bind(ClientLibrary);
export const initializeClient = ClientLibrary.initializeClient.bind(ClientLibrary);
export const initializeWasm = ClientLibrary.initializeWasm.bind(ClientLibrary);
export const injectTrapLinks = ClientLibrary.injectTrapLinks.bind(ClientLibrary);
export const solveChallengeAndRetry = ClientLibrary.solveChallengeAndRetry.bind(ClientLibrary);

// Export the internal object for testing purposes
export default ClientLibrary;

// --- Global Export for Browser ---
// Attach the library to the window object to make it accessible from inline scripts.
if (typeof window !== 'undefined') {
    window.ClientLibrary = ClientLibrary;
}