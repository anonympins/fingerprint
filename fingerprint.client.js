import { cyrb53, FingerprintBuilder } from './fingerprint.builder.js';
import { solveChallenge } from './pow.solver.js';

const ClientLibrary = {
    // Cache pour éviter de recalculer les constantes (Hardware, etc.)
    _cachedBuilder: null,
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
                "hw",
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

            // 7. Bot Detection (Indication cachée)
            if (nav.webdriver) this._cachedBuilder.add("bot", "true");
        }

        return this._cachedBuilder.toString();
    },

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
        const payloadHash = cyrb53(sortedPayload);
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
        this._cachedBuilder = null;
    },

    /**
     * Démarre le suivi des mouvements de la souris pour calculer l'entropie.
     * À appeler une fois sur la page.
     */
    startMouseEntropyTracker() {
        // S'assurer de ne pas attacher l'écouteur plusieurs fois
        if (mouseMovements > 0) return;

        document.addEventListener('mousemove', (e) => {
            const dx = e.clientX - lastMousePos.x;
            const dy = e.clientY - lastMousePos.y;
            // Une métrique simple : la somme des distances. Un bot aura souvent 0.
            metrics.mouseEntropy += Math.sqrt(dx * dx + dy * dy);
            lastMousePos = {x: e.clientX, y: e.clientY};
            mouseMovements++;
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
        // Ajoute un timestamp au moment de la collecte pour la détection de rejeu.
        metrics.clientTimestamp = Date.now();

        // Normalise l'entropie de la souris
        if (mouseMovements > 10) {
            metrics.mouseEntropy /= mouseMovements;
        }
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
    onHoneypotTrigger : () => {
        metrics.honeypotInteraction = true;
        // On pourrait même envoyer un signalement au serveur immédiatement.
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
    if (response.status !== 404 || !response.headers.get('content-type')?.includes('application/json')) {
      return response;
    }
    
    try {
      const challengeData = await response.json();
      if (!challengeData.challenge || !challengeData.challenge.type) {
        return response; // Pas un challenge JSON valide
      }

      console.log(`[Fingerprint] Received a '${challengeData.challenge.type}' challenge. Solving...`);
      const solution = await solveChallenge(challengeData.challenge);
      console.log('[Fingerprint] Challenge solved. Retrying original request.');

      // Ajouter la solution aux paramètres de la requête pour le nouvel essai
      const url = new URL((resource instanceof Request) ? resource.url : String(resource), window.location.origin);
      // Le type de challenge est maintenant `cpu_mem` pour les API
      url.searchParams.set('pow_type', 'cpu_mem');
      url.searchParams.set('pow_nonce', challengeData.challenge.nonce);

      // La solution est un objet { cpu: ..., mem: ... }. Le serveur attend pow_solution_cpu et pow_solution_mem.
      Object.entries(solution).forEach(([key, value]) => {
        url.searchParams.set(`pow_solution_${key}`, String(value));
      });

      // On utilise la chaîne d'intercepteurs pour la requête réessayée,
      // ce qui garantit que le fetch original est appelé avec le bon contexte.
      // Cela évite de réintroduire l'erreur "Illegal invocation".
      return window.fetch(url.toString(), options);
    } catch (e) {
      console.error('[Fingerprint] Failed to solve or retry challenge:', e);
      return response; // Retourne la réponse 429 originale en cas d'échec
    }
  },
/**
 * @typedef {object} ClientConfig
 * @property {boolean} [mouse=true] - Activer le suivi de l'entropie de la souris.
 * @property {boolean} [keystrokes=true] - Activer le suivi de la dynamique de frappe.
 * @property {string[]} [honeypots] - Noms des champs de formulaire honeypot à initialiser.
 * @property {object} [fetch] - Configuration pour l'interception de fetch.
 * @property {string[]} [fetch.targetDomains] - Domaines à protéger. Si non fourni, protège les requêtes de même origine.
 */

/**
 * Initialise toutes les protections côté client en une seule fois.
 * C'est la méthode d'initialisation recommandée.
 * @param {ClientConfig} [config={}] - L'objet de configuration.
 */
  initializeClient(config = {}) {
    const {
        mouse = true,
        keystrokes = true,
        honeypots = [],
        fetch: fetchConfig = {},
    } = config;

    if (mouse) {
        this.startMouseEntropyTracker();
    }
    if (keystrokes) {
        this.startKeystrokeDynamicsTracker();
    }
    if (honeypots.length > 0) {
        this.initializeHoneypots(honeypots);
    }
    // On active l'interception si `fetch` est configuré, même avec un objet vide.
    if (config.fetch) {
        this.initializeFetch(fetchConfig.targetDomains);

        // Ajoute l'intercepteur pour la résolution de challenge
        if (fetchConfig.handleChallenges !== false) {
          this.addFetchInterceptor(async (resource, options, next) => {
            const response = await next(resource, options);
            return this.solveChallengeAndRetry(response, resource, options);
          });
        }
    }
  }
};

/**
 * @typedef {object} ClientBehaviorMetrics
 * @property {number} mouseEntropy - Entropie des mouvements de la souris.
 * @property {number} keystrokeLatency - Latence moyenne entre les frappes.
 * @property {boolean} honeypotInteraction - Vrai si un honeypot a été touché.
 * @property {number} clientTimestamp - Timestamp (Date.now()) de la collecte des métriques.
 */

/** @type {ClientBehaviorMetrics} */
const metrics = {
    mouseEntropy: 0,
    keystrokeLatency: 0,
    honeypotInteraction: false,
    clientTimestamp: 0,
};

let lastMousePos = { x: 0, y: 0 };
let mouseMovements = 0;
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
export const initializeHoneypots = ClientLibrary.initializeHoneypots.bind(ClientLibrary);
export const getClientBehaviorMetrics = ClientLibrary.getClientBehaviorMetrics.bind(ClientLibrary);
export const protectedFetch = ClientLibrary.protectedFetch.bind(ClientLibrary);
export const addFetchInterceptor = ClientLibrary.addFetchInterceptor.bind(ClientLibrary);
export const patchGlobalFetch = ClientLibrary.patchGlobalFetch.bind(ClientLibrary);
export const initializeFetch = ClientLibrary.initializeFetch.bind(ClientLibrary);
export const initializeClient = ClientLibrary.initializeClient.bind(ClientLibrary);
export const solveChallengeAndRetry = ClientLibrary.solveChallengeAndRetry.bind(ClientLibrary);

// Export the internal object for testing purposes
export default ClientLibrary;