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

        // Poids de "véracité" (Entropie/Stabilité)
        const weights = {
            cvs: 4.0,   // Canvas: Très haute entropie (Rendu unique)
            gpu: 3.0,   // GPU: Haute entropie (Matériel spécifique)
            hw: 1.5,    // Hardware: Moyenne entropie
            scr: 1.0,   // Screen: Moyenne
            geo: 0.5,   // Geo: Faible (VPN/Voyage)
            os: 0.5,    // OS: Faible (Générique)
            bot: 0.0,   // Bot: Informatif
        };

        let weightedMatches = 0;
        let totalWeight = 0;

        const allKeys = new Set([...map1.keys(), ...map2.keys()]);

        allKeys.forEach((key) => {
            const weight = weights[key] || 1.0;
            totalWeight += weight;
            if (map1.get(key) === map2.get(key)) {
                weightedMatches += weight;
            }
        });

        return totalWeight === 0 ? 0 : weightedMatches / totalWeight;
    }
}