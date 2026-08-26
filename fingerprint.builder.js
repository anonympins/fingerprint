/**
 * Algorithme de hachage cyrb53 (rapide et faible taux de collision).
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
     * Adds a raw component without hashing it.
     * Useful for metrics that need to be read on the server.
     * @param {string} group - The name of the group.
     * @param {string|number} value - The raw value.
     */
    addRaw(group, value) {
        if (value === undefined || value === null) return this;
        this.components.set(group, value);
        return this;
    }

    /**
     * Affiche les composants actuels dans la console.
     * @param {string} [title='FingerprintBuilder Components'] - Un titre pour le log.
     */
    log(title = 'FingerprintBuilder Components') {
        console.log(`--- ${title} ---`);
        const sortedComponents = Array.from(this.components.entries())
            .sort((a, b) => a[0].localeCompare(b[0]));
        
        console.table(Object.fromEntries(sortedComponents));
        console.log(`Final string: ${this.toString()}`);
        console.log(`---------------------------------${'-'.repeat(title.length)}`);
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
        * Adds a raw component without hashing it.
        * Useful for metrics that need to be read on the server.
    * @param {string} group - The name of the group.
    * @param {string|number} value - The raw value.
    */
    addRaw(group, value) {
        if (value === undefined || value === null) return this;
        this.components.set(group, value);
        return this;
    }

    /**
     * Compares two fingerprints and returns a similarity score (0 to 1).
     * Uses weights to give more importance to strong invariants (Canvas, GPU).
     * @param {string} fpString1 - Fingerprint A
     * @param {string} fpString2 - Fingerprint B
     */
    static compare(fpString1, fpString2) {
        if (!fpString1 || !fpString2) return 0;

        const parse = (str) => new Map(str.split("|").map(part => part.split(":")).filter(([k,v]) => k && v));

        const map1 = parse(fpString1);
        const map2 = parse(fpString2);

        // Keys to ignore when comparing the initial request fingerprint with the challenge solver's fingerprint.
        // Headers like Client-Hints (ch_*), cookie presence (cookie_keys), and upgrade-insecure-requests
        // can vary or be absent on the subsequent request that submits the solution, especially after a redirect.
        // By ignoring them, we focus the comparison on more stable identifiers like UA, JA3, GPU, etc.
        const volatileKeys = new Set([
            'ch_ua', 'ch_platform', 'ch_mobile', 'ch_model', 'ch_arch', 'ch_bitness',
            'cookie_keys', 'upgrade',
            // Also ignore network and http version as they can change between requests (e.g., proxy, protocol upgrade)
            'network', 'http_ver',
            // Ignore proxy-related headers as they are not stable client identifiers
            'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip'
        ]);

        // Poids de "véracité" (Entropie/Stabilité)
        // Les poids sont augmentés pour donner plus d'importance aux signaux forts.
        const weights = {
            // --- Signaux très forts (difficiles à usurper) ---
            cvs: 5.0,   // Canvas: Très haute entropie (Rendu unique du GPU/driver)
            gpu: 4.0,   // GPU: Haute entropie (Matériel spécifique)
            ja3: 3.5,   // JA3: Identifie la librairie TLS (très stable pour un client donné)
            ua: 2.0,    // User-Agent: Signal fort, bien que modifiable
            
            // --- Signaux composites et dérivés ---
            client_fp_hash: 3.0, // Le hash de l'empreinte client est un signal très fort.
            browser: 1.5,        // Le navigateur extrait du UA.
            os_version: 1.5,     // L'OS extrait du UA.
            device_type: 1.0,    // Le type d'appareil extrait du UA.

            // --- Signaux moyens ---
            hw: 1.5,    // Hardware (CPU, RAM): Stabilité moyenne
            scr: 1.0,   // Screen: Stabilité moyenne
            // 'os' est souvent la même chose que 'ch_platform', on peut le déprécier ou lui donner un poids faible.
            os: 0.8,    // OS (nav.platform): Assez stable
            geo: 0.5,   // Geo/Langue: Peut changer (VPN, voyage)
        };

        let weightedMatches = 0;
        let totalWeight = 0;

        const allKeys = new Set([...map1.keys(), ...map2.keys()]);

        allKeys.forEach((key) => {
            // On ignore les clés volatiles pour cette comparaison spécifique.
            if (volatileKeys.has(key)) return;

            // On ne compare que les clés qui ont un poids défini.
            const weight = weights[key];
            if (!weight) return;

            totalWeight += weight; // N'incrémenter que si la clé est pertinente.
            if (map1.get(key) === map2.get(key)) {
                weightedMatches += weight;
            }
        });

        return totalWeight === 0 ? 0 : weightedMatches / totalWeight;
    }
}