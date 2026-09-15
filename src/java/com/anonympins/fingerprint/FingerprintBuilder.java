package com.anonympins.fingerprint;

import java.util.*;

public class FingerprintBuilder {
    private final Map<String, String> components = new TreeMap<>();

    public FingerprintBuilder add(String group, Object value) {
        if (value == null || "".equals(value)) {
            return this;
        }
        this.components.put(group, cyrb53(value.toString(), 0));
        return this;
    }

    public FingerprintBuilder addRaw(String group, Object value) {
        if (value == null) {
            return this;
        }
        this.components.put(group, value.toString());
        return this;
    }

    @Override
    public String toString() {
        List<String> parts = new ArrayList<>();
        for (Map.Entry<String, String> entry : components.entrySet()) {
            parts.add(entry.getKey() + ":" + entry.getValue());
        }
        return String.join("|", parts);
    }

    public static String cyrb53(String str, int seed) {
        int h1 = 0xdeadbeef ^ seed;
        int h2 = 0x41c6ce57 ^ seed;
        for (int i = 0; i < str.length(); i++) {
            int ch = str.charAt(i);
            h1 = (h1 ^ ch) * -1640531535;
            h2 = (h2 ^ ch) * 1597334677;
        }
        h1 = (h1 ^ (h1 >>> 16)) * -2048144789 ^ (h2 ^ (h2 >>> 13)) * -1028477387;
        h2 = (h2 ^ (h2 >>> 16)) * -2048144789 ^ (h1 ^ (h1 >>> 13)) * -1028477387;

        long unsignedH1 = h1 & 0xFFFFFFFFL;
        long unsignedH2 = h2 & 0xFFFFFFFFL;
        long valH2 = 4294967296L * (2097151L & unsignedH2) + unsignedH1;
        return Long.toUnsignedString(valH2);
    }

    public static double compare(String fp1, String fp2) {
        if (fp1 == null || fp1.isEmpty() || fp2 == null || fp2.isEmpty()) {
            return 0.0;
        }

        Map<String, String> map1 = parse(fp1);
        Map<String, String> map2 = parse(fp2);

        Set<String> volatileKeys = new HashSet<>(Arrays.asList(
            "ch_ua", "ch_platform", "ch_mobile", "ch_model", "ch_arch", "ch_bitness",
            "cookie_keys", "upgrade", "network", "http_ver",
            "x_forwarded_for", "x_real_ip", "cf_connecting_ip"
        ));

        Map<String, Double> weights = new HashMap<>();
        weights.put("cvs", 5.0);
        weights.put("gpu", 4.0);
        weights.put("ja3", 3.5);
        weights.put("ja4", 4.0);
        weights.put("ja4s", 4.0);
        weights.put("ja4h", 3.8);
        weights.put("h2_settings", 3.0);
        weights.put("tcp_fp", 2.5);
        weights.put("ua", 2.0);
        weights.put("client_fp_hash", 3.0);
        weights.put("browser", 1.5);
        weights.put("os_version", 1.5);
        weights.put("device_type", 1.0);
        weights.put("hw", 1.5);
        weights.put("scr", 1.0);
        weights.put("os", 0.8);
        weights.put("geo", 0.5);

        double weightedMatches = 0.0;
        double totalWeight = 0.0;

        Set<String> allKeys = new HashSet<>();
        allKeys.addAll(map1.keySet());
        allKeys.addAll(map2.keySet());

        for (String key : allKeys) {
            if (volatileKeys.contains(key)) {
                continue;
            }

            Double weight = weights.get(key);
            if (weight == null) {
                continue;
            }

            totalWeight += weight;
            if (map1.containsKey(key) && map2.containsKey(key)) {
                if (map1.get(key).equals(map2.get(key))) {
                    weightedMatches += weight;
                }
            }
        }

        return totalWeight == 0.0 ? 0.0 : weightedMatches / totalWeight;
    }

    private static Map<String, String> parse(String fpStr) {
        Map<String, String> map = new HashMap<>();
        for (String part : fpStr.split("\\|")) {
            String[] pair = part.split(":", 2);
            if (pair.length == 2 && !pair[0].isEmpty() && !pair[1].isEmpty()) {
                map.put(pair[0], pair[1]);
            }
        }
        return map;
    }
}