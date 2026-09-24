/**
 * cyrb53 hashing algorithm (fast with low collision rate).
 */
// Exported for fallback usage by fingerprint.client.js
export const cyrb53 = (str, seed = 0) => { 
    const safeStr = (typeof str === 'string' ? str : String(str || '')).slice(0, 10000);
    let h1 = 0xdeadbeef ^ seed,
        h2 = 0x41c6ce57 ^ seed;
    for (let i = 0, ch; i < safeStr.length; i++) {
        ch = safeStr.charCodeAt(i);
        h1 = Math.imul(h1 ^ ch, 2654435761); // Use Math.imul for 32-bit multiplication
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
 * Class for constructing a composite fingerprint (Multi-Hash).
 * Output format: "grp1:hash1|grp2:hash2|grp3:hash3"
 */
export class FingerprintBuilder {
    constructor() {
        // The hasher is an instance property so it can be overridden by the WASM client.
        this.components = new Map();
        // Default hasher set to the JavaScript cyrb53 implementation.
        this.hasher = cyrb53;
    }

    /**
     * Adds a component to the global hash.
     * @param {string} group - Component group identifier (e.g. 'hw', 'screen', 'geo').
     * @param {string|number|boolean} value - Raw value to hash.
     */
    add(group, value) {
        if (value === undefined || value === null) return this;
        // Hash the value individually to anonymize and normalize length
        this.components.set(group, this.hasher(String(value)));
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
     * Prints current components to the console.
     * @param {string} [title='FingerprintBuilder Components'] - Title for output display.
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
     * Produces the final serialized signature string.
     * Keys are sorted to guarantee deterministic serialization.
     */
    toString() {
        return Array.from(this.components.entries())
            .sort((a, b) => a[0].localeCompare(b[0])) // Alphabetical key ordering
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
    // Note on `volatileKeys`: These keys are ignored during the comparison between the fingerprint
    // of the request that *triggered* a challenge and the fingerprint of the request that *submits*
    // the solution. This is because headers like Client-Hints (ch_*), cookie presence, and upgrade-insecure-requests
    // can legitimately change or be absent on the subsequent request, especially after a redirect.
    // By ignoring them, we focus the comparison on more stable identifiers like UA, JA3, GPU, etc.
    static compare(fpString1, fpString2) {
        if (!fpString1 || !fpString2) return 0;

        const parse = (str) => new Map(str.split("|").map(part => part.split(":")).filter(([k,v]) => k && v));

        const map1 = parse(fpString1);
        const map2 = parse(fpString2);

        const volatileKeys = new Set([
            'ch_ua', 'ch_platform', 'ch_mobile', 'ch_model', 'ch_arch', 'ch_bitness',
            'cookie_keys', 'upgrade',
            'network', 'http_ver',
            'x_forwarded_for', 'x_real_ip', 'cf_connecting_ip'
        ]);

        // Entropy / stability reliability weights
        // Strongly invariant signals receive higher weighting
        const weights = {
            // --- High-entropy invariants (tamper-resistant) ---
            cvs: 5.0,   // Canvas: High entropy (GPU/driver rendering quirks)
            gpu: 4.0,   // GPU: High entropy (Physical graphics chipset)
            ja3: 3.5,   // JA3: TLS client stack fingerprint
            ja4: 4.0,   // JA4: Modern TLS fingerprint including HTTP/2
            h2: 3.0, // HTTP/2 settings frame fingerprint
            tcp: 2.5, // TCP/IP fingerprint
            ua: 2.0,    // User-Agent string
            
            // --- Derived / composite signals ---
            client_fp_hash: 3.0, // Client-side fingerprint hash
            browser: 1.5,        // Parsed browser family
            os_version: 1.5,     // Parsed OS family
            device_type: 1.0,    // Device form factor

            // --- Medium-stability signals ---
            hw: 1.5,    // Hardware (cores, RAM): Moderate stability
            scr: 1.0,   // Screen geometry: Moderate stability
            os: 0.8,    // OS (nav.platform)
            geo: 0.5,   // Geo/locale: Subject to VPNs and travel
        };

        let weightedMatches = 0;
        let totalWeight = 0;

        const allKeys = new Set([...map1.keys(), ...map2.keys()]);

        allKeys.forEach((key) => {
            // Ignore volatile keys during comparative evaluation
            if (volatileKeys.has(key)) {
                return;
            }

            const weight = weights[key] ?? 0;
            // Only tally total weight if key is present in at least one fingerprint
            if (!map1.has(key) && !map2.has(key)) return;

            totalWeight += weight;
            if (map1.get(key) === map2.get(key)) {
                weightedMatches += weight;
            }
        });

        return totalWeight === 0 ? 0 : weightedMatches / totalWeight;
    }
}