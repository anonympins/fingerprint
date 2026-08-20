import crypto from "node:crypto";

const POW_SECRET = process.env.POW_SECRET;

if (!POW_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('POW_SECRET environment variable is not set. This is required for production.');
} else if (!POW_SECRET) {
  console.warn('Warning: POW_SECRET environment variable not set. Using a default, insecure secret for development.');
}
/**
 * Algorithme de hachage cyrb53 (rapide et faible taux de collision). Exporté pour réutilisation.
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
 * Classe pour construire une empreinte composite (Multi-Hash).
 * Format de sortie : "grp1:hash1|grp2:hash2|grp3:hash3"
 */
export class FingerprintBuilder {
  constructor() {
    this.components = new Map();
  }

  /**
   * Ajoute un composant au hash global.
   * @param {string} group - Le nom du groupe (ex: 'hw', 'screen', 'geo')
   * @param {string|number|boolean} value - La valeur brute à hasher
   */
  add(group, value) {
    if (value === undefined || value === null) return this;
    // On hash la valeur individuellement pour l'anonymiser et réduire sa taille
    this.components.set(group, cyrb53(String(value)));
    return this;
  }

  /**
   * Génère la chaîne de signature finale.
   * Trie les clés pour garantir un ordre déterministe.
   */
  toString() {
    return Array.from(this.components.entries())
      .sort((a, b) => a[0].localeCompare(b[0])) // Tri alphabétique des clés
      .map(([key, hash]) => `${key}:${hash}`)
      .join("|");
  }

  /**
   * Compare deux empreintes et retourne un score de similarité (0 à 1).
   * Utilise des poids pour donner plus d'importance aux invariants forts (Canvas, GPU).
   * @param {string} fpString1 - Empreinte A
   * @param {string} fpString2 - Empreinte B
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

    // Poids de "véracité" (Entropie/Stabilité)
    const weights = {
      cvs: 4.0, // Canvas: Très haute entropie (Rendu unique)
      gpu: 3.0, // GPU: Haute entropie (Matériel spécifique)
      hw: 1.5, // Hardware: Moyenne entropie
      scr: 1.0, // Screen: Moyenne
      geo: 0.5, // Geo: Faible (VPN/Voyage)
      os: 0.5, // OS: Faible (Générique)
      bot: 0.0, // Bot: Informatif
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

/**
 * Génère le contenu HTML pour un challenge TSP (Traveling Salesperson Problem).
 * @param {string} nonce - Nonce unique pour le challenge.
 * @param {number} numCities - Nombre de villes à inclure dans le problème.
 * @param {number} targetMaxDistance - Distance maximale acceptable pour la solution.
 * @param {Array<{x: number, y: number}>} cities - Coordonnées des villes.
 * @param {string} path - Chemin de redirection après résolution.
 * @returns {string} HTML de la page de challenge.
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
        <head><title>Vérification de sécurité Avancée (Niveau 3)</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Vérification Ultime (Niveau 3)</h1>
          <p>Veuillez résoudre ce petit problème d'optimisation pour prouver que vous êtes humain.</p>
          <div id="loader" style="margin:20px;">⚙️ Calcul d'itinéraire en cours... (${numCities} villes)</div>
          <script>
            const cities = ${citiesJson};
            const nonce = "${nonce}";
            const targetMaxDistance = ${targetMaxDistance};

            // Fonction utilitaire pour calculer la distance entre deux villes
            function distance(city1, city2) {
                return Math.sqrt(Math.pow(city1.x - city2.x, 2) + Math.pow(city1.y - city2.y, 2));
            }

            // Fonction utilitaire pour évaluer la distance totale d'un chemin
            function evaluatePathDistance(cities, path) {
                let totalDistance = 0;
                for (let i = 0; i < path.length - 1; i++) {
                    totalDistance += distance(cities[path[i]], cities[path[i + 1]]);
                }
                totalDistance += distance(cities[path[path.length - 1]], cities[path[0]]); // Retour au départ
                return totalDistance;
            }

            // Solveur simple du TSP (heuristique du plus proche voisin)
            function solveTspNearestNeighbor(cities) {
                const numCities = cities.length;
                if (numCities === 0) return [];

                let currentPath = [];
                let visited = new Array(numCities).fill(false);

                let currentCityIndex = 0; // Toujours commencer par la première ville pour la reproductibilité
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
              // Pour ne pas freezer le navigateur, on yield le thread de temps en temps
              await new Promise(resolve => setTimeout(resolve, 10));
              const solutionPath = solveTspNearestNeighbor(cities);
              const solutionDistance = evaluatePathDistance(cities, solutionPath);

              if (solutionDistance <= targetMaxDistance) {
                window.location.href = "${path}" + "?pow_type=tsp&pow_nonce=" + nonce + "&pow_solution=" + JSON.stringify(solutionPath);
              } else {
                document.getElementById('loader').innerText = "Erreur: Impossible de trouver une solution suffisante. Veuillez réessayer.";
              }
            }
            solve();
          </script>
        </body>
      </html>`;
};

/**
 * Vérifie une solution de PoW TSP.
 * @param {string} nonce - Nonce du challenge.
 * @param {string} solutionPathJson - Chemin proposé par le client (JSON stringifié).
 * @param {number} numCities - Nombre de villes du challenge.
 * @param {number} targetMaxDistance - Distance maximale acceptable.
 * @param {Array<{x: number, y: number}>} cities - Coordonnées des villes.
 * @returns {boolean} True si la solution est valide.
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

    // Vérifier que le chemin est une permutation valide des villes
    const uniqueCities = new Set(solutionPath);
    if (
      uniqueCities.size !== numCities ||
      Math.min(...solutionPath) < 0 ||
      Math.max(...solutionPath) >= numCities
    )
      return false;

    // Recalculer la distance côté serveur
    let totalDistance = 0;
    let totalPenalty = 0;

    // Fonction pour calculer l'angle entre 3 points (p1 -> p2 -> p3)
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

      // 1. Calcul de la distance du segment
      totalDistance += Math.sqrt(Math.pow(cities[p1_idx].x - cities[p2_idx].x, 2) + Math.pow(cities[p1_idx].y - cities[p2_idx].y, 2));

      // 2. Calcul de la pénalité de virage
      const angle = calculateAngle(
        cities[p1_idx],
        cities[p2_idx],
        cities[p3_idx],
      );
      if (angle < 45) {
        // Pénalité pour les virages très serrés (< 45 degrés)
        totalPenalty += (45 - angle) * 5; // La pénalité est proportionnelle à l'acuité de l'angle
      }
    }

    const finalScore = totalDistance + totalPenalty;
    return finalScore <= targetMaxDistance;
  } catch (e) {
    console.error("Erreur lors de la vérification du challenge TSP:", e);
    return false;
  }
};

/**
 * Génère le contenu HTML pour le challenge PoW CPU (SHA-256).
 */
const generateCpuPoWChallenge = (
  clientIp,
  nonce,
  difficulty = 4,
  path = "",
) => {
  return `
      <html>
        <head><title>Vérification de sécurité</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Un instant... (Niveau 1)</h1>
          <p>Nous vérifions que vous n'êtes pas un bot. Cela prend quelques secondes.</p>
          <div id="loader" style="margin:20px;">⚙️ Calcul de sécurité CPU en cours...</div>
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
                if (solution % 100000 === 0) await new Promise(resolve => setTimeout(resolve, 0)); // Pour ne pas freezer le navigateur
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
 * Génère le contenu HTML pour un challenge PoW gourmand en mémoire.
 */
const generateMemoryPoWChallenge = (
  clientIp,
  nonce,
  difficulty = 16,
  path = "",
) => {
  // difficulty ici est la taille du buffer en Mo.
  return `
      <html>
        <head><title>Vérification de sécurité Avancée</title></head>
        <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
          <h1>Vérification renforcée... (Niveau 2)</h1>
          <p>Votre activité nécessite une vérification de sécurité supplémentaire.</p>
          <div id="loader" style="margin:20px;">⚙️ Allocation et calcul mémoire en cours... (${difficulty} Mo)</div>
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
                document.getElementById('loader').innerText = "Erreur: Mémoire insuffisante. Veuillez rafraîchir.";
              }
            }
            solve();
          </script>
        </body>
      </html>`;
};

/**
 * Vérifie si une solution PoW est valide et génère un ticket de passage.
 */
export const verifyPoWAndGenerateTicket = (
  ip,
  nonce,
  solution,
  difficulty = 4,
) => {
  // 1. Vérifier la solution : hash(ip + nonce + solution) doit commencer par N zéros
  const hash = crypto
    .createHash("sha256")
    .update(`${ip}:${nonce}:${solution}`)
    .digest("hex");

  if (!hash.startsWith("0".repeat(difficulty))) {
    return null;
  }

  // 2. Générer un ticket HMAC pour que le client n'ait plus à le refaire pendant 1h
  const expiry = Date.now() + 3600000; // 1 heure
  const signature = crypto
    .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
    .update(`${ip}:${expiry}`)
    .digest("hex");

  return `${expiry}:${signature}`;
};

/**
 * Vérifie une solution de PoW mémoire.
 * Le serveur refait le même calcul pour valider.
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

  // Utilisation de timingSafeEqual pour éviter les attaques temporelles
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig));
};

/**
 * Crée un hash stable basé sur les caractéristiques de l'appareil, indépendamment de l'IP.
 * C'est notre "empreinte de niveau 2".
 * @param {object} req - L'objet de la requête Express.
 * @returns {string} Un hash représentant l'appareil.
 */
function getDeviceHash(req) {
  const srv = new FingerprintBuilder();
  srv.add("ua", req.headers["user-agent"]);
  if (req.headers["sec-ch-ua-platform"])
    srv.add("os", req.headers["sec-ch-ua-platform"]);
  if (req.headers["sec-ch-ua"]) srv.add("ch", req.headers["sec-ch-ua"]);
  return srv.toString(); // Retourne la chaîne de caractères complète de l'empreinte pour une comparaison détaillée.
}

/**
 * Calcule les indicateurs de suspicion liés aux anomalies des headers HTTP.
 * @param {object} req - L'objet de la requête Express.
 * @returns {{headerAnomalyScore: number}}
 */
function getHeaderAnomalies(req, consistencyScore) {
  // FIX: consistencyScore est maintenant passé
  let anomalyScore = 0;
  // Pénalité forte si le User-Agent est manquant ou très court (signe de script simple)
  if (!req.headers["user-agent"] || req.headers["user-agent"].length < 10) {
    anomalyScore += 60;
  }
  // Pénalité si le header Accept-Language est manquant
  if (!req.headers["accept-language"]) {
    anomalyScore += 25;
  }
  // Pénalité pour les requêtes HTTP/1.0, souvent utilisées par des outils anciens ou des bots
  if (req.httpVersion === "1.0") {
    anomalyScore += 15;
  }

  // NOUVEAU : Score d'incohérence (cookie volé ?)
  // Si le score de cohérence est bas, on ajoute une pénalité massive.
  // Un score de 0.2 signifie une différence énorme.
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
 * Implémentation par défaut du store, en mémoire.
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
 * Permet de configurer un datastore externe (ex: Redis).
 * Doit être appelée avant que le middleware ne soit utilisé.
 * @param {IStore} externalStore - Une implémentation de l'interface IStore.
 */
export const configureStore = (externalStore) => {
  store = externalStore;
};

/**
 * Orchestre l'identification de la requête en utilisant une ancre persistante (cookie)
 * et une vérification par empreinte.
 * @param {object} req - L'objet de la requête Express.
 * @param {object} res - L'objet de la réponse Express (pour poser le cookie).
 * @returns {Promise<{deviceId: string, deviceData: object, consistencyScore: number}>}
 */
async function resolveRequestIdentity(req, res) {
  const existingDeviceId = req.cookies?.device_id;
  const currentDeviceHash = getDeviceHash(req);
  let deviceId = existingDeviceId;
  let consistencyScore = 1.0; // 1.0 = parfaitement cohérent
  let deviceData = null;

  if (deviceId) {
    deviceData = await store.get(`device:${deviceId}`);
  }

  if (deviceData) {
    // Cas 1: L'utilisateur a un "passeport" et nous le connaissons.
    const storedHash = deviceData.initialDeviceHash;

    // Comparaison de l'empreinte actuelle avec celle de référence.
    consistencyScore = FingerprintBuilder.compare(
      storedHash,
      currentDeviceHash,
    );
  } else {
    // Cas 2: Nouvel utilisateur ou cookie perdu/invalide.
    deviceId = crypto.randomUUID(); // On génère un nouveau "passeport".

    // On pose le cookie de manière sécurisée.
    res.cookie("device_id", deviceId, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 31536000000, // 1 an
    });

    // On initialise le suivi pour ce nouvel appareil.
    deviceData = {
      initialDeviceHash: currentDeviceHash, // On ancre l'empreinte initiale.
      ips: new Set(),
      lastUpdate: Date.now(),
      lastFpHash: currentDeviceHash,
      lastChangeTimestamp: 0,
      rapidChangeCount: 0,
    };
    // L'écriture se fera dans getSuspicionVector après toutes les modifications.
  }

  return { deviceId, deviceData, consistencyScore };
}

/*
 * Calcule les indicateurs de suspicion liés au comportement de l'appareil (historique, rotation).
 * @param {object} req - L'objet de la requête Express.
 * @param {object} deviceData - Les données d'activité de l'appareil.
 * @returns {Promise<{historyScore: number, rotationScore: number}>}
 */
async function getBehavioralIndicators(req, deviceData) {
  const now = Date.now();
  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";

  // On récupère le type d'IP pour moduler le score
  const ipProfile = (await store.get(`ip:${clientIp}`)) || { type: "residential" };
  const isSharedIp = ipProfile.type === "shared";

  const currentFpHash = getDeviceHash(req); // On utilise le hash de l'appareil

  // --- Analyse de comportement (Fréquence de changement) ---
  if (deviceData.lastFpHash && currentFpHash !== deviceData.lastFpHash) {
    const timeSinceLastChange = now - deviceData.lastChangeTimestamp;

    if (timeSinceLastChange < RAPID_CHANGE_THRESHOLD_MS) {
      deviceData.rapidChangeCount = Math.min(
        deviceData.rapidChangeCount + 1,
        MAX_RAPID_CHANGES_PER_DEVICE * 2,
      ); // Augmente rapidement
    } else {
      deviceData.rapidChangeCount = Math.max(0, deviceData.rapidChangeCount - 1); // Diminue lentement
    }
    deviceData.lastChangeTimestamp = now;
  }

  deviceData.lastFpHash = currentFpHash;
  deviceData.ips.add(clientIp); // On enregistre l'IP utilisée par cet appareil

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

  // Score basé sur la rotation rapide d'identité (0-100)
  const rotationScore = Math.min(
    100,
    (deviceData.rapidChangeCount / MAX_RAPID_CHANGES_PER_DEVICE) * 100,
  );

  return { historyScore, rotationScore };
}

/**
 * Retourne un vecteur de scores de suspicion bruts (non pondérés).
 * @param {object} req - L'objet de la requête Express.
 * @returns {Promise<{historyScore: number, rotationScore: number, headerAnomalyScore: number, inconsistencyScore: number}>}
 */
export async function getSuspicionVector(req, res) {
  const { deviceId, deviceData, consistencyScore } = await resolveRequestIdentity(req, res);

  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
  await store.set(`ip-device:${clientIp}`, deviceId); // On lie l'IP à l'appareil

  // Nettoyage périodique des données de l'appareil
  if (Date.now() - deviceData.lastUpdate > 10 * 60 * 1000) { // 10 minutes
    deviceData.ips.clear();
    deviceData.rapidChangeCount = 0;
  }
  deviceData.lastUpdate = Date.now();

  const behavioral = await getBehavioralIndicators(req, deviceData);
  const anomalies = getHeaderAnomalies(req, consistencyScore);

  // Sauvegarde l'état mis à jour de l'appareil dans le store
  await store.set(`device:${deviceId}`, deviceData);

  return { ...behavioral, ...anomalies };
}

// Un utilisateur résidentiel peut changer de réseau (maison, 4G, wifi public).
const MAX_DISTINCT_IPS_PER_DEVICE = 15;
// Un utilisateur derrière un NAT/proxy ne devrait pas utiliser BEAUCOUP d'autres IPs.
const MAX_DISTINCT_IPS_FOR_SHARED_USER = 5;

// Une IP est considérée comme "partagée" si elle est utilisée par plus de 50 appareils différents en 10 minutes.
const SHARED_IP_DEVICE_THRESHOLD = 50;

const RAPID_CHANGE_THRESHOLD_MS = 2000; // 2 secondes
const MAX_RAPID_CHANGES_PER_DEVICE = 3; // Nombre de changements rapides d'empreinte autorisés par appareil.

/**
 * Identifie une requête côté serveur de manière granulaire.
 * Utilise le FingerprintBuilder pour créer une empreinte basée sur les headers
 * et l'IP, rendant le spoofing plus complexe (nécessite de changer toute la stack).
 */
export const identifyRequest = async (req, res) => {
  const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
  const deviceId = req.cookies?.device_id;

  // --- Mise à jour de la réputation de l'IP ---
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
    // Logique anti "Bot Amnésique" améliorée
    ipProfile.statelessCount++;
  }

  // Si une IP voit trop d'appareils différents, on la classe comme "partagée".
  if (ipProfile.deviceIds.size > SHARED_IP_DEVICE_THRESHOLD) {
    ipProfile.type = "shared";
  }

  // Si une IP résidentielle fait trop de requêtes sans cookie, c'est un bot.
  // Pour une IP partagée, on est plus tolérant car de nouveaux utilisateurs arrivent constamment.
  const statelessLimit = ipProfile.type === "shared" ? 50 : 10;
  if (ipProfile.statelessCount > statelessLimit) {
    return `suspicious_high:${clientIp}`;
  }
  await store.set(`ip:${clientIp}`, ipProfile);

  // Pour la compatibilité avec le rate-limiter, on calcule un score simple.
  // Le PoW utilisera le système pondéré, plus complexe.
  const vector = await getSuspicionVector(req, res);
  const score =
    vector.historyScore * 0.3 +
    vector.rotationScore * 0.5 +
    vector.headerAnomalyScore * 0.1 +
    vector.inconsistencyScore * 0.8; // L'incohérence est un signal très fort

  // On retourne une chaîne de caractères pour la compatibilité avec les rate limiters,
  // mais basée sur les seuils de suspicion.
  // NOTE : Ces seuils sont fixes ici, mais le PoW utilisera les seuils dynamiques.
  if (score >= 75) {
    return `suspicious_high:${clientIp}`;
  }
  if (score >= 40) {
    return `suspicious_medium:${clientIp}`;
  }

  // Pour les requêtes normales, on retourne un hash de l'empreinte pour le rate limiting.
  // On utilise le hash de l'appareil pour que le rate-limit suive l'appareil, pas l'IP.
  const deviceIdForIp = await store.get(`ip-device:${clientIp}`);
  const finalDeviceId = deviceId || deviceIdForIp || clientIp;
  return `device:${finalDeviceId}`;
};
// --- NOUVEAU CHALLENGE CPU "ANALOGIQUE" ---

// Le plus grand nombre possible avec SHA-256 (2^256 - 1)
const MAX_DIFFICULTY_TARGET = 2n ** 256n - 1n;
// Une difficulté de base, ex: nécessite que les 16 premiers bits soient à 0
// (équivalent à 4 zéros en hexadécimal)
const BASE_TARGET = MAX_DIFFICULTY_TARGET >> 16n;

/**
 * Calcule le target de difficulté en fonction du facteur de suspicion.
 * @param {number} suspicionFactor - Un nombre de 0 à 1.
 * @returns {BigInt} Le nombre cible.
 */
export function calculateTarget(suspicionFactor) {
  // Plage de difficulté ajustée pour être réaliste.
  // MIN_DIFFICULTY: Assez rapide pour ne pas gêner un utilisateur légèrement suspect.
  // MAX_DIFFICULTY: Assez lent pour pénaliser lourdement un bot, mais faisable pour un humain patient (5-30s).
  const MIN_DIFFICULTY_BITS = 18; // Valeur par défaut, devrait être configurable
  const MAX_DIFFICULTY_BITS = 26; // Valeur par défaut, devrait être configurable

  // On utilise une interpolation linéaire entre la difficulté min et max.
  const totalDifficultyBits =
    MIN_DIFFICULTY_BITS +
    suspicionFactor * (MAX_DIFFICULTY_BITS - MIN_DIFFICULTY_BITS);

  // Le target est le max / 2^bits
  return MAX_DIFFICULTY_TARGET >> BigInt(Math.floor(totalDifficultyBits));
}

/**
 * Génère un challenge CPU basé sur un target.
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
    target: target.toString(16), // On envoie le target en hexadécimal
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
    // On injecte les détails du challenge dans l'objet window pour que le script externe puisse les lire.
    const challengeData = JSON.stringify({
        type: 'cpu_target',
        ip: clientIp,
        nonce: nonce,
        target: target,
        path: path
    });

    return `
      <html><head><title>Security Check</title></head>
      <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
        <h1>Please wait... (Level 1)</h1>
        <p>We are verifying that you are not a bot. This may take a few seconds.</p>
        <div id="loader" style="margin:20px;">⚙️ Performing CPU security calculation...</div>
        
        <!-- On passe les données du challenge au script via un objet global -->
        <script>window.powChallenge = ${challengeData};</script>

        <!-- On charge le script client qui contient la logique de résolution -->
        <!-- Ce chemin '/js/fingerprint.client.js' doit être servi par votre app Express -->
        <script src="/js/fingerprint.client.js" defer></script>

        <script>
          // Le script externe va maintenant lire window.powChallenge et exécuter le solveur.
        </script>
      </body></html>`;
}

/**
 * Vérifie une solution de PoW basée sur un target et génère un ticket.
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
    // La comparaison est directe avec les BigInt natifs
    // La preuve est valide, on génère le ticket
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
export const powMiddleware = (securityConfig) => async (req, res, next) => {
    // On ignore le PoW pour les ressources statiques (images, scripts, fonts)
    if (isStaticResource(req)) {
        return next();
    }
    
    const isProduction = process.env.NODE_ENV === 'production';
    const { weights, thresholds } = securityConfig;

    const clientIp = req.ip || req.socket?.remoteAddress || "unknown";
    // On récupère le vecteur de suspicion et on calcule le score final pondéré
    const suspicionVector = await getSuspicionVector(req, res);

    const finalScore =
        suspicionVector.historyScore * weights.historyScore +
        suspicionVector.rotationScore * weights.rotationScore +
        suspicionVector.headerAnomalyScore * weights.headerAnomalyScore +
        suspicionVector.inconsistencyScore * weights.inconsistencyScore;

    const isSuspiciousHigh = finalScore >= thresholds.high;
    const isSuspiciousMedium = finalScore >= thresholds.medium;
    const isSuspicious = finalScore >= thresholds.low;

    // Calcul d'un "facteur de suspicion" analogique (0 à 1+) pour une difficulté progressive
    const suspicionFactor = isSuspicious
        ? Math.min(
            1,
            (finalScore - thresholds.low) / (thresholds.high - thresholds.low),
        )
        : 0;
    const powCookie = req.cookies?.pow_clearance;
    const { pow_type, pow_nonce, pow_solution, captcha_token } = req.query;

    if (isSuspicious && !isTicketValid(clientIp, powCookie)) {
        // --- GESTION DES RÉPONSES AUX CHALLENGES ---
        if (pow_nonce && pow_solution) {
            let isValid = false,
                ticket = null;
            if (pow_type === "cpu_target") {
                // On vérifie le nouveau type
                ticket = verifyCpuTargetPoWAndGenerateTicket(
                    clientIp,
                    pow_nonce,
                    pow_solution,
                    suspicionFactor, // On passe directement le facteur analogique
                );
                isValid = ticket !== null;
            } else if (pow_type === "mem") {
                const minDifficulty = 16; // 16Mo
                const maxDifficulty = 48; // 48Mo
                const difficulty =
                    minDifficulty + suspicionFactor * (maxDifficulty - minDifficulty);
                isValid = verifyMemoryPoW(pow_nonce, pow_solution, difficulty);
            } else if (pow_type === "tsp") {
                // La logique pour TSP reste la même
                // ...
            }

            if (isValid) {
                if (!ticket) {
                    // Si le ticket n'a pas déjà été généré (cas CPU)
                    const expiry = Date.now() + 3600000; // 1 heure
                    const signature = crypto
                        .createHmac("sha256", POW_SECRET || "fallback-dev-secret-32-chars-minimum")
                        .update(`${clientIp}:${expiry}`)
                        .digest("hex");
                    ticket = `${expiry}:${signature}`;
                }

                res.cookie("pow_clearance", ticket, {
                    httpOnly: true,
                    secure: isProduction,
                    maxAge: 3600000,
                });
                return res.redirect(req.path); // Recharge la page sans les params
            }
        }

        // --- SÉLECTION ET ENVOI DU CHALLENGE APPROPRIÉ ---
        const nonce = crypto.randomBytes(16).toString("hex");

        // NIVEAU 3 : CAPTCHA (le plus élevé)
        if (isSuspiciousHigh) {
            // ... logique pour le challenge TSP/Captcha
        }

        // NIVEAU 2 : PoW Gourmand en Mémoire
        if (isSuspiciousMedium) {
            const minDifficulty = 16; // 16Mo
            const maxDifficulty = 48; // 48Mo
            const difficulty =
                minDifficulty + suspicionFactor * (maxDifficulty - minDifficulty);
            return res.status(429).send(
                generateMemoryPoWChallenge(clientIp, nonce, difficulty, req.path),
                // NOTE: Pour que le challenge mémoire fonctionne, il faudra aussi
                // l'intégrer dans `generateChallengePage` et le script client.
            );
        }
        // NIVEAU 1 : PoW CPU Standard
        if (isSuspicious) {
            // On récupère les détails du challenge
            const challengeDetails = generateCpuTargetChallenge(
                clientIp,
                nonce,
                suspicionFactor,
                req.path,
            );
            // On génère la page HTML avec le solveur intégré
            const challengePage = generateCpuTargetChallengePage(challengeDetails, clientIp);
            return res.status(429).send(challengePage);
        }
    }
    next();
};
