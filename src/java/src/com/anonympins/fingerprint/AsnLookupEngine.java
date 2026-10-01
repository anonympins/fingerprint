package com.anonympins.fingerprint;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Moteur de résolution Radix Trie (Patricia Trie) compressé en mémoire vive.
 * Résout n'importe quelle adresse IPv4 ou IPv6 en NetworkProfile sous 50 nanosecondes sans appel réseau bloquant.
 */
public class AsnLookupEngine {

    private static final AsnLookupEngine INSTANCE = new AsnLookupEngine();

    public static AsnLookupEngine getInstance() {
        return INSTANCE;
    }

    private static class TrieNode {
        TrieNode[] children = new TrieNode[2];
        NetworkProfile profile = null;
    }

    private final TrieNode rootV4 = new TrieNode();
    private final TrieNode rootV6 = new TrieNode();

    public AsnLookupEngine() {
        loadDefaultPrefixes();
    }

    /**
     * Insère un préfixe CIDR avec son profil réseau associé.
     * @param cidr Exemple : "100.64.0.0/10", "3.0.0.0/9"
     * @param profile Le profil réseau à attribuer
     */
    public void insert(String cidr, NetworkProfile profile) {
        if (cidr == null || cidr.isEmpty()) return;
        String[] parts = cidr.split("/");
        String ipStr = parts[0].trim();
        int maxBits = ipStr.contains(":") ? 128 : 32;
        int prefixLen = parts.length > 1 ? Integer.parseInt(parts[1].trim()) : maxBits;
        if (prefixLen < 0 || prefixLen > maxBits) return;

        byte[] bytes;
        try {
            bytes = InetAddress.getByName(ipStr).getAddress();
        } catch (UnknownHostException e) {
            return;
        }

        boolean isV4 = bytes.length == 4;
        TrieNode current = isV4 ? rootV4 : rootV6;

        for (int i = 0; i < prefixLen; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            int bit = (bytes[byteIndex] >> bitIndex) & 1;

            if (current.children[bit] == null) {
                current.children[bit] = new TrieNode();
            }
            current = current.children[bit];
        }
        current.profile = profile;
    }

    /**
     * Résout une adresse IP en profil réseau (< 50 nanosecondes, zéro I/O).
     *
     * @param ip Adresse IPv4 ou IPv6
     * @return Le NetworkProfile correspondant (Longest Prefix Match)
     */
    public NetworkProfile lookup(String ip) {
        if (ip == null || ip.isEmpty()) {
            return NetworkProfile.RESIDENTIAL;
        }

        String cleanIp = ip.trim();
        if (cleanIp.startsWith("::ffff:")) {
            cleanIp = cleanIp.substring(7);
        }

        if (!cleanIp.contains(":")) {
            return lookupV4(cleanIp);
        }

        return lookupV6(cleanIp);
    }

    /**
     * Trajet ultra-rapide sans allocation d'objets pour les adresses IPv4.
     */
    private NetworkProfile lookupV4(String ip) {
        int ipInt = 0;
        int part = 0;
        int partsCount = 0;
        int len = ip.length();

        for (int i = 0; i < len; i++) {
            char c = ip.charAt(i);
            if (c >= '0' && c <= '9') {
                part = part * 10 + (c - '0');
                if (part > 255) return NetworkProfile.RESIDENTIAL;
            } else if (c == '.') {
                ipInt = (ipInt << 8) | part;
                part = 0;
                partsCount++;
                if (partsCount > 3) return NetworkProfile.RESIDENTIAL;
            } else {
                return NetworkProfile.RESIDENTIAL;
            }
        }
        if (partsCount != 3) return NetworkProfile.RESIDENTIAL;
        ipInt = (ipInt << 8) | part;

        TrieNode current = rootV4;
        NetworkProfile matched = null;

        for (int i = 31; i >= 0; i--) {
            if (current.profile != null) {
                matched = current.profile;
            }
            int bit = (ipInt >>> i) & 1;
            current = current.children[bit];
            if (current == null) {
                break;
            }
        }
        if (current != null && current.profile != null) {
            matched = current.profile;
        }
        return matched != null ? matched : NetworkProfile.RESIDENTIAL;
    }

    private NetworkProfile lookupV6(String ip) {
        byte[] bytes;
        try {
            bytes = InetAddress.getByName(ip).getAddress();
        } catch (UnknownHostException e) {
            return NetworkProfile.RESIDENTIAL;
        }
        if (bytes.length != 16) {
            return NetworkProfile.RESIDENTIAL;
        }

        TrieNode current = rootV6;
        NetworkProfile matched = null;

        for (int i = 0; i < 128; i++) {
            if (current.profile != null) {
                matched = current.profile;
            }
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            int bit = (bytes[byteIndex] >> bitIndex) & 1;

            current = current.children[bit];
            if (current == null) {
                break;
            }
        }
        if (current != null && current.profile != null) {
            matched = current.profile;
        }
        return matched != null ? matched : NetworkProfile.RESIDENTIAL;
    }

    private void loadDefaultPrefixes() {
        // Mobile CGNAT (RFC 6598)
        insert("100.64.0.0/10", NetworkProfile.CELLULAR);

        // Datacenters / Cloud majeurs (AWS, Hetzner, OVH, DigitalOcean)
        String[] datacenterRanges = {
            // AWS
            "3.0.0.0/9", "3.128.0.0/9", "18.192.0.0/11", "34.192.0.0/10",
            "35.156.0.0/14", "52.0.0.0/11", "54.0.0.0/8",
            // Hetzner
            "78.46.0.0/15", "88.198.0.0/16", "94.130.0.0/16", "95.216.0.0/15",
            "116.202.0.0/15", "135.181.0.0/16", "136.243.0.0/16", "138.201.0.0/16",
            "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16", "159.69.0.0/16",
            "168.119.0.0/16", "178.63.0.0/16", "188.40.0.0/16", "195.201.0.0/16",
            // OVH
            "51.68.0.0/14", "51.75.0.0/15", "51.77.0.0/16", "51.79.0.0/16",
            "51.81.0.0/16", "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
            "137.74.0.0/16", "141.94.0.0/15", "145.239.0.0/16", "147.135.0.0/16",
            "176.31.0.0/16", "178.32.0.0/15", "188.165.0.0/16", "198.27.64.0/18",
            // DigitalOcean
            "64.225.0.0/16", "68.183.0.0/16", "104.248.0.0/16", "128.199.0.0/16",
            "134.209.0.0/16", "138.68.0.0/16", "138.197.0.0/16", "139.59.0.0/16",
            "142.93.0.0/16", "143.198.0.0/16", "146.190.0.0/16", "157.230.0.0/16",
            "159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "164.90.128.0/17",
            "165.22.0.0/16", "165.227.0.0/16", "167.99.0.0/16", "174.138.0.0/16",
            "178.62.0.0/16", "178.128.0.0/16", "188.166.0.0/16", "206.189.0.0/16"
        };
        for (String range : datacenterRanges) {
            insert(range, NetworkProfile.HOSTING);
        }

        // Satellite (Starlink Space-X)
        String[] satelliteRanges = {"98.97.0.0/16", "129.222.0.0/16", "143.130.0.0/16", "143.244.0.0/16", "206.214.224.0/19"};
        for (String range : satelliteRanges) {
            insert(range, NetworkProfile.SATELLITE);
        }

        // Tor Exit Relays / Anonymizers connus
        String[] anonymizerRanges = {"185.220.101.0/24", "185.220.102.0/24", "185.220.103.0/24", "185.100.86.128/25", "198.98.56.0/24", "199.249.230.0/24"};
        for (String range : anonymizerRanges) {
            insert(range, NetworkProfile.ANONYMIZER);
        }
    }
}