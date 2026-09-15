package com.anonympins.fingerprint;

import java.util.*;

public class RequestContext {
    public String clientIp = "";
    public String path = "";
    public Map<String, String> headers = new HashMap<>();
    public Map<String, Object> queryParams = new HashMap<>();
    public Map<String, Object> body = null;
    public Map<String, String> cookies = new HashMap<>();
    public String httpVersion = "1.1";
    public long requestTimestamp;
    public String tlsSessionId = null;
    public String ja3 = null;
    public String ja4 = null;
    public String ja3Raw = null; // Raw ClientHello for server-side JA3 calculation
    public String http2Fingerprint = null;
    public String tcpFingerprint = null;
    public String quicFingerprint = null;
    public String zkpY = null;

    public RequestContext(String clientIp, String path, Map<String, String> headers,
                          Map<String, Object> queryParams, Map<String, Object> body,
                          Map<String, String> cookies, String httpVersion) {
        this.clientIp = clientIp;
        this.path = path;
        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                this.headers.put(entry.getKey().toLowerCase(), entry.getValue());
            }
        }
        this.queryParams = queryParams != null ? queryParams : new HashMap<>();
        this.body = body;
        this.cookies = cookies != null ? cookies : new HashMap<>();
        this.httpVersion = httpVersion != null ? httpVersion : "1.1";
        this.requestTimestamp = System.currentTimeMillis();

        this.ja3 = this.headers.get("x-ja3-hash");
        this.ja4 = this.headers.get("x-ja4-hash");
        this.ja3Raw = this.headers.get("x-ja3-raw");
        this.ja3 = this.headers.get("x-ja3-hash");
        this.ja4 = this.headers.get("x-ja4-hash");
        this.http2Fingerprint = this.headers.get("x-http2-fingerprint");
        this.tcpFingerprint = this.headers.get("x-tcp-fingerprint");
        this.quicFingerprint = this.headers.get("x-quic-fp");
        this.tlsSessionId = this.headers.getOrDefault("x-tls-session-id", this.headers.get("x-ssl-session-id"));
        String zkpProof = this.headers.get("x-zkp-proof");
        if (zkpProof != null && !zkpProof.isEmpty()) {
            this.zkpY = zkpProof.split(":")[0];
        }
    }

    public String getHeader(String name) {
        return this.headers.get(name.toLowerCase());
    }
}