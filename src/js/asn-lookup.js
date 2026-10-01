import { isIPv4, isIPv6 } from "node:net";

/**
 * Profils de réseaux et paramètres de modulation pour le scoring analogique.
 */
export const NetworkProfile = {
  RESIDENTIAL: {
    type: 'RESIDENTIAL',
    baseScore: 0.0,
    inflectionPoint: 0.72,
    toleranceRotation: false,
    jitterTolerance: 60.0
  },
  CELLULAR: {
    type: 'CELLULAR',
    baseScore: 10.0,
    inflectionPoint: 0.60,
    toleranceRotation: true,
    jitterTolerance: 80.0
  },
  SATELLITE: {
    type: 'SATELLITE',
    baseScore: 15.0,
    inflectionPoint: 0.68,
    toleranceRotation: false,
    jitterTolerance: 150.0
  },
  HOSTING: {
    type: 'HOSTING',
    baseScore: 55.0,
    inflectionPoint: 0.85,
    toleranceRotation: false,
    jitterTolerance: 30.0
  },
  ANONYMIZER: {
    type: 'ANONYMIZER',
    baseScore: 85.0,
    inflectionPoint: 0.90,
    toleranceRotation: false,
    jitterTolerance: 40.0
  }
};

/**
 * Nœud compact pour l'arbre Radix binaire.
 */
class TrieNode {
  constructor() {
    this.children = [null, null]; // 0 et 1
    this.profile = null;
  }
}

/**
 * Patricia Trie / Radix Trie en mémoire vive pour résolution IPv4/IPv6 sous 50ns.
 */
export class AsnLookupEngine {
  constructor() {
    this.rootV4 = new TrieNode();
    this.rootV6 = new TrieNode();
    this.loadDefaultPrefixes();
  }

  /**
   * Insère un préfixe CIDR avec son profil réseau associé.
   * @param {string} cidr Ex: "100.64.0.0/10", "198.51.100.0/24"
   * @param {object} profile Configuration du NetworkProfile
   */
  insert(cidr, profile) {
    const [ip, prefixLenStr] = cidr.split('/');
    const isV4 = isIPv4(ip);
    const isV6 = isIPv6(ip);
    if (!isV4 && !isV6) return;

    const maxBits = isV4 ? 32 : 128;
    const prefixLen = prefixLenStr !== undefined ? parseInt(prefixLenStr, 10) : maxBits;
    if (isNaN(prefixLen) || prefixLen < 0 || prefixLen > maxBits) return;

    let current = isV4 ? this.rootV4 : this.rootV6;
    const bits = this._ipToBits(ip, isV4);

    for (let i = 0; i < prefixLen; i++) {
      const bit = bits[i];
      if (!current.children[bit]) {
        current.children[bit] = new TrieNode();
      }
      current = current.children[bit];
    }
    current.profile = profile;
  }

  /**
   * Résout une adresse IP en profil réseau (< 50 nanosecondes, sans I/O).
   * @param {string} ip
   * @returns {typeof NetworkProfile.RESIDENTIAL}
   */
  lookup(ip) {
    if (!ip || typeof ip !== 'string') return NetworkProfile.RESIDENTIAL;

    let cleanIp = ip.trim().toLowerCase();
    if (cleanIp.startsWith('::ffff:')) {
      cleanIp = cleanIp.substring(7);
    }

    const isV4 = isIPv4(cleanIp);
    const isV6 = isIPv6(cleanIp);
    if (!isV4 && !isV6) return NetworkProfile.RESIDENTIAL;

    let current = isV4 ? this.rootV4 : this.rootV6;
    let matchedProfile = null;
    const bits = this._ipToBits(cleanIp, isV4);

    for (let i = 0; i < bits.length; i++) {
      if (current.profile !== null) {
        matchedProfile = current.profile; // Longest-Prefix-Match
      }
      const bit = bits[i];
      current = current.children[bit];
      if (!current) break;
    }

    if (current && current.profile !== null) {
      matchedProfile = current.profile;
    }

    return matchedProfile || NetworkProfile.RESIDENTIAL;
  }

  /**
   * Convertit une adresse IP en tableau de bits (0 et 1).
   * @private
   */
  _ipToBits(ip, isV4) {
    if (isV4) {
      const octets = ip.split('.').map(Number);
      const bits = new Uint8Array(32);
      let idx = 0;
      for (let i = 0; i < 4; i++) {
        const byte = octets[i];
        for (let b = 7; b >= 0; b--) {
          bits[idx++] = (byte >> b) & 1;
        }
      }
      return bits;
    } else {
      let normalized = ip;
      if (normalized.includes("::")) {
        const parts = normalized.split("::");
        const left = parts[0] ? parts[0].split(":") : [];
        const right = parts[1] ? parts[1].split(":") : [];
        const missing = 8 - (left.length + right.length);
        const middle = Array(missing).fill("0000");
        normalized = [...left, ...middle, ...right].join(":");
      }
      const groups = normalized.split(":").map(g => parseInt(g, 16) || 0);
      const bits = new Uint8Array(128);
      let idx = 0;
      for (let i = 0; i < 8; i++) {
        const word = groups[i];
        for (let b = 15; b >= 0; b--) {
          bits[idx++] = (word >> b) & 1;
        }
      }
      return bits;
    }
  }

  /**
   * Charge les plages fondamentales (Cloud providers, Tor, Mobile CGNAT, Satellite).
   */
  loadDefaultPrefixes() {
    // Mobile CGNAT (RFC 6598)
    this.insert('100.64.0.0/10', NetworkProfile.CELLULAR);

    // Réseaux Datacenters / Cloud majeurs (AWS, OVH, Hetzner, DigitalOcean)
    const datacenterRanges = [
      // AWS
      '3.0.0.0/9', '3.128.0.0/9', '18.192.0.0/11', '34.192.0.0/10',
      '35.156.0.0/14', '52.0.0.0/11', '54.0.0.0/8',
      // Hetzner
      '78.46.0.0/15', '88.198.0.0/16', '94.130.0.0/16', '95.216.0.0/15',
      '116.202.0.0/15', '135.181.0.0/16', '136.243.0.0/16', '138.201.0.0/16',
      '142.132.0.0/16', '144.76.0.0/16', '148.251.0.0/16', '159.69.0.0/16',
      '168.119.0.0/16', '178.63.0.0/16', '188.40.0.0/16', '195.201.0.0/16',
      // OVH
      '51.68.0.0/14', '51.75.0.0/15', '51.77.0.0/16', '51.79.0.0/16',
      '51.81.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16',
      '137.74.0.0/16', '141.94.0.0/15', '145.239.0.0/16', '147.135.0.0/16',
      '176.31.0.0/16', '178.32.0.0/15', '188.165.0.0/16', '198.27.64.0/18',
      // DigitalOcean
      '64.225.0.0/16', '68.183.0.0/16', '104.248.0.0/16', '128.199.0.0/16',
      '134.209.0.0/16', '138.68.0.0/16', '138.197.0.0/16', '139.59.0.0/16',
      '142.93.0.0/16', '143.198.0.0/16', '146.190.0.0/16', '157.230.0.0/16',
      '159.65.0.0/16', '159.89.0.0/16', '161.35.0.0/16', '164.90.128.0/17',
      '165.22.0.0/16', '165.227.0.0/16', '167.99.0.0/16', '174.138.0.0/16',
      '178.62.0.0/16', '178.128.0.0/16', '188.166.0.0/16', '206.189.0.0/16'
    ];

    for (const range of datacenterRanges) {
      this.insert(range, NetworkProfile.HOSTING);
    }

    // Satellite (ex: Starlink Space-X)
    const satelliteRanges = [
      '98.97.0.0/16', '129.222.0.0/16', '143.130.0.0/16',
      '143.244.0.0/16', '206.214.224.0/19'
    ];
    for (const range of satelliteRanges) {
      this.insert(range, NetworkProfile.SATELLITE);
    }

    // Anonymizers / Tor Exit Relays connus
    const anonymizerRanges = [
      '185.220.101.0/24', '185.220.102.0/24', '185.220.103.0/24',
      '185.100.86.128/25', '198.98.56.0/24', '199.249.230.0/24'
    ];
    for (const range of anonymizerRanges) {
      this.insert(range, NetworkProfile.ANONYMIZER);
    }
  }
}

export const defaultAsnLookup = new AsnLookupEngine();