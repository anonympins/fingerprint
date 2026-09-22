package com.anonympins.fingerprint;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Decodifica nativamente un TLS ClientHello per calcolare JA3 e JA4.
 */
public class TLSClientHelloParser {

    private static final Set<Integer> GREASE_VALUES = new HashSet<>(Arrays.asList(
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    ));

    public static Long readVarInt(ByteBuffer buffer) {
        if (!buffer.hasRemaining()) return null;
        int first = buffer.get() & 0xFF;
        int prefix = first >> 6;
        long firstVal = first & 0x3F;

        if (prefix == 0) {
            return firstVal;
        } else if (prefix == 1) {
            if (buffer.remaining() < 1) return null;
            return (firstVal << 8) | (buffer.get() & 0xFF);
        } else if (prefix == 2) {
            if (buffer.remaining() < 3) return null;
            long val = (firstVal << 24)
                    | ((buffer.get() & 0xFF) << 16)
                    | ((buffer.get() & 0xFF) << 8)
                    | (buffer.get() & 0xFF);
            return val;
        } else {
            if (buffer.remaining() < 7) return null;
            long val = firstVal;
            for (int i = 0; i < 7; i++) {
                val = (val << 8) | (buffer.get() & 0xFF);
            }
            return val;
        }
    }

    public static Map<Long, Object> parseQuicTransportParameters(byte[] data) {
        Map<Long, Object> params = new LinkedHashMap<>();
        if (data == null || data.length == 0) return params;
        ByteBuffer buffer = ByteBuffer.wrap(data);

        while (buffer.hasRemaining()) {
            Long paramId = readVarInt(buffer);
            if (paramId == null) break;
            Long paramLenLong = readVarInt(buffer);
            if (paramLenLong == null) break;
            int paramLen = paramLenLong.intValue();
            if (buffer.remaining() < paramLen) break;

            byte[] paramBytes = new byte[paramLen];
            buffer.get(paramBytes);

            if (paramLen > 0 && Arrays.asList(1L, 3L, 4L, 5L, 6L, 7L, 8L, 9L, 11L, 14L).contains(paramId)) {
                ByteBuffer valBuf = ByteBuffer.wrap(paramBytes);
                Long val = readVarInt(valBuf);
                params.put(paramId, val != null ? val : HexFormat.of().formatHex(paramBytes));
            } else {
                params.put(paramId, HexFormat.of().formatHex(paramBytes));
            }
        }
        return params;
    }

    public static Map<String, Object> parseQuicControlFrames(byte[] streamData) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> frames = new ArrayList<>();
        List<String> frameOrder = new ArrayList<>();
        Map<Long, Long> settings = new HashMap<>();

        if (streamData == null || streamData.length == 0) {
            result.put("frames", frames);
            result.put("frame_order", "");
            result.put("settings", settings);
            return result;
        }

        ByteBuffer buffer = ByteBuffer.wrap(streamData);
        if (buffer.hasRemaining() && (buffer.get(0) & 0xFF) == 0x00) {
            buffer.get();
        }

        while (buffer.hasRemaining()) {
            Long frameType = readVarInt(buffer);
            if (frameType == null) break;
            Long frameLenLong = readVarInt(buffer);
            if (frameLenLong == null) break;
            int frameLen = frameLenLong.intValue();
            if (buffer.remaining() < frameLen) break;

            byte[] payload = new byte[frameLen];
            buffer.get(payload);

            String abbr = "u";
            if (frameType == 0x04) abbr = "s";
            else if (frameType == 0x12 || frameType == 0x02) abbr = "m";
            else if (frameType == 0x0f || frameType == 0xaf || frameType == 0xf0700L) abbr = "p";
            else if (frameType == 0x10 || frameType == 0x0d) abbr = "d";
            else if (frameType == 0x07) abbr = "g";

            Map<String, Object> frameInfo = new HashMap<>();
            frameInfo.put("type", frameType);
            frameInfo.put("length", frameLen);
            frames.add(frameInfo);
            frameOrder.add(abbr);

            if (frameType == 0x04) {
                ByteBuffer pBuf = ByteBuffer.wrap(payload);
                while (pBuf.hasRemaining()) {
                    Long sId = readVarInt(pBuf);
                    if (sId == null) break;
                    Long sVal = readVarInt(pBuf);
                    if (sVal == null) break;
                    settings.put(sId, sVal);
                }
            }
        }

        result.put("frames", frames);
        result.put("frame_order", String.join(",", frameOrder));
        result.put("settings", settings);
        return result;
    }

    public static String formatQuicFingerprint(Map<Long, Object> params, String priority, String frameOrder) {
        List<String> paramParts = new ArrayList<>();
        for (Map.Entry<Long, Object> entry : params.entrySet()) {
            paramParts.add(entry.getKey() + "=" + entry.getValue());
        }
        String fp = "1;" + String.join(",", paramParts);
        if ((priority != null && !priority.isEmpty()) || (frameOrder != null && !frameOrder.isEmpty())) {
            fp += ";" + (priority != null ? priority : "");
        }
        if (frameOrder != null && !frameOrder.isEmpty()) {
            fp += ";" + frameOrder;
        }
        return fp;
    }

    public static Map<String, String> parse(byte[] binary) {
        if (binary == null || binary.length < 43) return null;
        // Verifica record handshake (0x16) e ClientHello (0x01)
        if ((binary[0] & 0xFF) != 0x16 || (binary[5] & 0xFF) != 0x01) return null;

        try {
            ByteBuffer buffer = ByteBuffer.wrap(binary);
            // Salta intestazioni standard fino alla lunghezza del Session ID
            buffer.position(43); 

            int sessionLen = buffer.get() & 0xFF;
            buffer.position(buffer.position() + sessionLen);

            int ciphersLen = buffer.getShort() & 0xFFFF;
            List<Integer> ciphers = new ArrayList<>();
            for (int i = 0; i < ciphersLen; i += 2) {
                ciphers.add(buffer.getShort() & 0xFFFF);
            }

            int compressionLen = buffer.get() & 0xFF;
            buffer.position(buffer.position() + compressionLen);

            if (buffer.remaining() < 2) return null;
            int extensionsLen = buffer.getShort() & 0xFFFF;
            int extLimit = buffer.position() + extensionsLen;

            List<Integer> extensions = new ArrayList<>();
            List<Integer> curves = new ArrayList<>();
            List<Integer> points = new ArrayList<>();
            List<Integer> sigAlgs = new ArrayList<>();
            List<Integer> supportedVersions = new ArrayList<>();
            boolean hasSni = false;
            String alpnProtocol = "";
            Map<Long, Object> quicParams = null;

            while (buffer.position() < extLimit && buffer.remaining() >= 4) {
                int extType = buffer.getShort() & 0xFFFF;
                int extLen = buffer.getShort() & 0xFFFF;

                if (buffer.remaining() < extLen) break;
                int nextPosition = buffer.position() + extLen;

                extensions.add(extType);

                if (extType == 0) {
                    hasSni = true;
                } else if (extType == 10 && extLen >= 2) {
                    int curvesLen = buffer.getShort() & 0xFFFF;
                    for (int j = 0; j < curvesLen; j += 2) {
                        curves.add(buffer.getShort() & 0xFFFF);
                    }
                } else if (extType == 11 && extLen >= 1) {
                    int pointsLen = buffer.get() & 0xFF;
                    for (int j = 0; j < pointsLen; j++) {
                        points.add(buffer.get() & 0xFF);
                    }
                } else if (extType == 13 && extLen >= 2) {
                    int sigAlgsLen = buffer.getShort() & 0xFFFF;
                    for (int j = 0; j < sigAlgsLen; j += 2) {
                        sigAlgs.add(buffer.getShort() & 0xFFFF);
                    }
                } else if (extType == 16 && extLen >= 3) {
                    int alpnListLen = buffer.getShort() & 0xFFFF;
                    if (alpnListLen > 0) {
                        int alpnStrLen = buffer.get() & 0xFF;
                        byte[] alpnBytes = new byte[alpnStrLen];
                        buffer.get(alpnBytes);
                        alpnProtocol = new String(alpnBytes, "UTF-8");
                    }
                } else if (extType == 43 && extLen >= 1) {
                    int versionsLen = buffer.get() & 0xFF;
                    for (int j = 0; j < versionsLen; j += 2) {
                        supportedVersions.add(buffer.getShort() & 0xFFFF);
                    }
                } else if (extType == 57 || extType == 0xffa5) { // quic_transport_parameters (RFC 9001 / draft)
                    if (extLen > 0 && buffer.remaining() >= extLen) {
                        byte[] quicData = new byte[extLen];
                        buffer.get(quicData);
                        quicParams = parseQuicTransportParameters(quicData);
                    }
                }
                buffer.position(nextPosition);
            }

            List<Integer> cleanCiphers = filterGrease(ciphers);
            List<Integer> cleanExtensions = filterGrease(extensions);
            List<Integer> cleanCurves = filterGrease(curves);
            List<Integer> cleanPoints = filterGrease(points);
            List<Integer> cleanSigAlgs = filterGrease(sigAlgs);
            List<Integer> cleanSupportedVersions = filterGrease(supportedVersions);

            int sslVersion = ((binary[9] & 0xFF) << 8) | (binary[10] & 0xFF);
            
            String ja3String = sslVersion + "," +
                    joinList(cleanCiphers, "-") + "," +
                    joinList(cleanExtensions, "-") + "," +
                    joinList(cleanCurves, "-") + "," +
                    joinList(cleanPoints, "-");

            // Generazione JA4
            int highestVersion = sslVersion;
            if (!cleanSupportedVersions.isEmpty()) {
                highestVersion = cleanSupportedVersions.stream().max(Integer::compare).orElse(sslVersion);
            }
            String ja4Version = highestVersion == 0x0304 ? "13" : "12";
            String sniStatus = hasSni ? "d" : "i";
            String numCiphers = String.format("%02d", Math.min(99, cleanCiphers.size()));
            String numExtensions = String.format("%02d", Math.min(99, cleanExtensions.size()));
            String ja4Alpn = alpnProtocol.isEmpty() ? "00" : (alpnProtocol.length() == 1 ? alpnProtocol + alpnProtocol : "" + alpnProtocol.charAt(0) + alpnProtocol.charAt(alpnProtocol.length() - 1));
            String ja4_a = "t" + ja4Version + sniStatus + numCiphers + numExtensions + ja4Alpn;

            List<Integer> sortedCiphers = new ArrayList<>(cleanCiphers);
            Collections.sort(sortedCiphers);
            String ciphersStr = sortedCiphers.stream().map(c -> String.format("%04x", c)).collect(Collectors.joining(","));
            String ja4_b = sha256(ciphersStr).substring(0, 12);

            List<Integer> sortedExtensions = new ArrayList<>(cleanExtensions);
            Collections.sort(sortedExtensions);
            String extensionsStr = sortedExtensions.stream().map(e -> String.format("%04x", e)).collect(Collectors.joining(","));
            List<Integer> sortedSigAlgs = new ArrayList<>(cleanSigAlgs);
            Collections.sort(sortedSigAlgs);
            String sigAlgsStr = sortedSigAlgs.stream().map(s -> String.format("%04x", s)).collect(Collectors.joining(","));
            String ja4_c = sha256(extensionsStr + "_" + sigAlgsStr).substring(0, 12);

            Map<String, String> result = new HashMap<>();
            result.put("ja3_string", ja3String);
            result.put("ja3_hash", md5(ja3String));
            result.put("ja4_raw", ja4_a + "_" + ja4_b + "_" + ja4_c);
            if (quicParams != null) {
                result.put("quic_fp", formatQuicFingerprint(quicParams, "", ""));
            }
            return result;
        } catch (Exception e) {
            return null;
        }
    }

    private static List<Integer> filterGrease(List<Integer> list) {
        return list.stream().filter(v -> !GREASE_VALUES.contains(v)).collect(Collectors.toList());
    }

    private static String joinList(List<Integer> list, String delimiter) {
        return list.stream().map(Object::toString).collect(Collectors.joining(delimiter));
    }

    private static String md5(String input) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(input.getBytes("UTF-8")));
    }

    private static String sha256(String input) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input.getBytes("UTF-8")));
    }
}