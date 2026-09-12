# Key Concepts and Suspicion Vectors

This document details the internal workings of the `fingerprint` protection engine. It explains how the system evaluates client legitimacy through multi-layered behavioral, cryptographic, and network analysis, and how these signals are translated into an overall suspicion score.

---

## Multi-Layered Decision Architecture

The library does not rely on a single binary signal to block a user. Instead, it orchestrates a set of **suspicion vectors** that measure specific anomalies at each level of the HTTP/S request:

1. **Transport & TLS Layer** (JA3/JA4 analysis, protocol negotiation).
2. **Application / Protocol Layer** (HTTP header structure, Client Hints, protocol consistency).
3. **Network Layer** (Local IP reputation, subnet/CIDR behavior).
4. **Global Identity Layer** (Session anchoring via device cookie vs. stable software/hardware fingerprint).
5. **Behavioral Layer** (Real interactions via mouse, keyboard, navigation, and frequency/sequence analysis).

Each detected anomaly generates a partial score (from 0 to 100). The final score is a **weighted sum** of these vectors, which is then compared against the enforcement thresholds defined in your security profile (`low`, `medium`, `high`, `block`).

---

## The 21 Suspicion Vectors Explained

### 1. History Score (`historyScore`)
* **Role**: Detect IP rotation (rotating residential proxies, botnets).
* **Mechanism**: The engine associates each unique device identifier (`device_id`) with the various IP addresses it uses over a given period. If a single device constantly changes its IP address (beyond the tolerance threshold configured for shared or mobile networks), the score increases drastically.

### 2. Rotation Score (`rotationScore`)
* **Role**: Detects attempts to rapidly spoof identity over a single connection.
* **Mechanism**: Measures how frequently fundamental, stable device fingerprint components (such as `canvas`, `gpu`, and `os`) change within extremely short timeframes (less than 2 seconds).

### 3. Header Anomaly Score (`headerAnomalyScore`)
* **Role**: Identifies standard automated scripts or tools (which often mimic browsers poorly).
* **Mechanism**: Analyzes the presence, order, and consistency of HTTP headers. Examples include:
* Missing or abnormally sized `User-Agent`.
* Missing `Accept-Language` header.
* Missing or incorrect `TE` header (e.g., desktop Firefox requires `TE: trailers`; its absence in Firefox, or its presence in Chrome, is considered suspicious).

### 4. Request Pattern Score (`requestPatternScore`)
* **Role**: Detects structured crawling, scraping, or API route brute-forcing.
* **Mechanism**: Analyzes a device's request history:
* **Temporal regularity**: Uses the standard deviation of time intervals between requests. A very low standard deviation indicates a timed bot (such as a cron job).
* **Benford's Law**: Analyzes the statistical distribution of intervals to determine if it appears natural. * **Path Enumeration**: Detects if the client is traversing sequential URLs (e.g., `/api/item/1`, `/api/item/2`, `/api/item/3`) by simply varying the parameters.

### 5. Cookie Inconsistency Score (`inconsistencyScore`)
* **Role**: Prevents session cookie theft (Cookie Hijacking) and identifier spoofing.
* **Mechanism**: Compares the client's current hardware fingerprint with the one recorded when the `device_id` cookie was initially generated. If an attacker attempts to reuse a device cookie on a machine with different hardware characteristics, consistency is lost, and the score immediately hits the maximum penalty level.

### 6. Behavioral Score (`behaviorScore`)
* **Role**: Validates that the user is human based on actual physical interactions with the page.
* **Mechanism**: The client-side script captures and transmits encrypted interaction metrics:
* **Mouse movements**: Analyzes speed, acceleration, and straightness (bots often trace perfectly straight lines at constant speeds without micro-pauses).
* **Keystroke dynamics**: Analyzes keyboard input latency. Latencies under 40 ms or overly monotonous patterns indicate automated input.
* **Browsing depth**: A very short browsing history (or a complete lack of prior interactions) raises suspicion, whereas a longer history boosts the trust score.

### 7. Honeypot Score (`honeypotScore`)
* **Role**: Instantly trap aggressive crawlers and vulnerability scanners.
* **Mechanism**: Triggers a 100% score if the client interacts with elements invisible to humans:
* Filling in hidden form fields (e.g., `email_confirm`, `admin`).
* Direct requests to sensitive or forbidden files/directories (e.g., `/wp-admin`, `/.env`, `/.git`).
* Malicious injection attempts (SQLi, XSS, RCE, Path Traversal, XXE) detected via built-in regex signatures or external advanced analyzers (such as ModSecurity or dynamic XSS filters).

### 8. Multi-Layer Inconsistency Score (`crossLayerInconsistencyScore`)
* **Role**: Detect software identity spoofing.
* **Mechanism**: Correlates information declared in the HTTP `User-Agent` with actual capabilities revealed by JavaScript API execution. For example: a client claiming to be on macOS in its HTTP header, while its JavaScript fingerprint reports a Windows system.

### 9. Temporal Inconsistency Score (`timeInconsistencyScore`)
* **Role**: Block behavioral telemetry replay attacks.
* **Mechanism**: Compares the internal timestamp generated by the client during behavioral data collection with the time the request is received by the server. If the time difference (delta) is abnormally high or shifted in time, the telemetry is considered replayed.

### 10. TLS Spoofing Score (`tlsSpoofingScore`)
* **Role**: Identify headless browsers and request tools (Python, Go, cURL) masquerading as standard browsers. * **How ​​it works**: Compares the cryptographic signature of the TLS handshake (JA3/JA4) with the expected signature for the browser declared in the `User-Agent`:
* A tool like `cURL` or `Python Requests` sending a "Chrome" User-Agent will be exposed because its TLS signature will not match Chrome's extension and cipher suite structures.
* Checks for the anomalous absence of the **GREASE** mechanism (mandatory in modern versions of Chrome/Edge).
* Detects if the HTTP/2 protocol is negotiated while the corresponding ALPN extension is missing from the TLS layer.

### 11. Automation Bot Score (`botScore`)
* **Role**: Detects browser automation frameworks (Selenium, Puppeteer, Playwright).
* **How ​​it works**: Inspects for the presence of specific global variables or debugging APIs introduced by client-side automation protocols (such as the Chrome DevTools Protocol—`CDP`—or WebDriver drivers).

### 12. Client Hints Inconsistency Score (`clientHintsInconsistencyScore`)
* **Role**: Detects partial or inconsistent User-Agent spoofing.
* **How ​​it works**: Compares modern identification data provided by Client Hints headers (e.g., `sec-ch-ua`, `sec-ch-ua-platform`) with the traditional `User-Agent`. A major discrepancy regarding the browser family or a significant version mismatch triggers this score.

### 13. Click Variance Score (`clickVarianceScore`)
* **Role**: Identifies automated clicks on forms or buttons.
* **How ​​it works**: Analyzes the mathematical precision of click coordinates (`x, y`) on a single interactive element. Humans rarely click on the exact same pixel twice; Zero or extremely low variance (less than 1 pixel) indicates the use of interface automation scripts.

### 14. Subnet Score (`subnetScore`)
* **Role**: Mitigate distributed attacks originating from the same network block.
* **Mechanism**: Groups client IP addresses by subnet (e.g., `/24` masks for IPv4, `/48` for IPv6). If numerous distinct devices within the same network block exhibit anomalous behavior or high scores simultaneously, the entire subnet incurs a progressive reputation penalty, governed by a time-decay algorithm (30-minute half-life).

### 15. IP Reputation Score (`ipReputationScore`)
* **Role**: Short-term historical tracking of individual IP addresses.
* **Mechanism**: Assigns a poor reputation score to an IP address if it has recently failed challenges or triggered security alerts. This score decreases with each hour of inactivity (a decay of 2 points per hour) to automatically rehabilitate legitimate, reassigned IP addresses.

### 16. Cookie Dropping Score (`cookieDroppingScore`)
* **Role**: Detects clients that refuse to store or return cookies (cookie-dropping attacks).
* **Mechanism**: When a client requests a page, the engine registers a temporary pending state for its IP. If subsequent requests from the same IP arrive shortly after without the expected `device_id` cookie, it indicates that the client is either deleting cookies or running in a stateless mode to bypass tracking, triggering a high penalty.

### 17. Threat Intel Score (`threatIntelScore`)
* **Role**: Leverages global threat intelligence feeds and known malicious IP lists.
* **Mechanism**: Automatically penalizes requests coming from known residential proxy exits, bulletproof hosting providers, Tor exit nodes, or active malicious infrastructure registered in the system's database or external threat intelligence feeds.

### 18. Botnet Cluster Score (`botnetClusterScore`)
* **Role**: Identifies distributed botnet waves sharing identical hardware profiles.
* **Mechanism**: Collects fingerprints and groups clients by their highly stable components (e.g., specific combinations of JA3/JA4, TCP, and GPU hashes). If multiple requests from different IPs (often across various geolocations or subnets) exhibit the exact same stable fingerprint within a short timeframe (e.g., 10 minutes), it indicates a coordinated botnet cluster using cloned device profiles.

### 19. TCP Anomaly Score (`tcpAnomalyScore`)
* **Role**: Detects OS-level spoofing at the transport layer.
* **Mechanism**: Inspects raw TCP SYN packets (specifically TTL, Window Size, MSS, Window Scale, and SACK permissions) to reconstruct the client's actual operating system. If the OS classified by the TCP/IP stack (e.g., Linux) differs from the OS claimed in the HTTP `User-Agent` (e.g., Windows), a high anomaly score is applied.

### 20. QUIC Anomaly Score (`quicAnomalyScore`)
* **Role**: Detects HTTP/3 client spoofing and framework emulation.
* **Mechanism**: Profiles the QUIC transport flow parameters (such as `initial_max_data`, `initial_max_streams_bidi`, and priority frame extensions). Since modern browsers like Chrome negotiate very specific default QUIC stream limits and frame priorities, handshakes that deviate from these defaults (e.g., tools like curl-impersonate or custom Go/Python packages) are instantly flagged.

### 21. Rendering Anomaly Score (`renderingAnomalyScore`)
* **Role**: Exposes headless browsers and virtualized graphics environments.
* **Mechanism**: Analyzes frame rendering telemetry sent by the client, such as vertical synchronization (V-Sync) patterns, frame-rate consistency (FPS), and rendering jitter. Automated headless clients running on virtual framebuffers or software-based GPU emulators (like SwiftShader) typically exhibit highly unstable frame times (high jitter) or abnormal FPS caps, and may trigger virtualized `OffscreenCanvas` exceptions.

---
## Mitigation Mechanisms: The Challenge System (PoW)

When a request exceeds configured suspicion thresholds, the engine does not display a definitive error page (unless the critical `block` threshold is surpassed). Instead, it imposes progressive cryptographic challenges via **Proof of Work (PoW)**, adjusting the effort required from the client based on their suspicion level.

```
[ HTTP Request ]
│
▼
Overall Score < Thresholds? ───────(Yes)───────> [ Access Granted ]
│
(No)
│
├─> "Low" Threshold  ─────> Standard CPU Challenge (Light PoW)
│
├─> "Med" Threshold  ─────> CPU Challenge + Memory Allocation (PoW blocking bot farms)
│
├─> "High" Threshold ─────> Human Optimization Challenge (TSP / Useful Work)
│
└─> "Block" Threshold ────> Immediate Block (Unlikely False Positive / Honeypot)
```

### Challenge Types

#### Target CPU Challenge (Level 1)
* **Target**: Low to moderate suspicion.
* **Principle**: The server sends a SHA-256 hashing challenge. The client must find a solution (an additional number) such that the combined hash begins with a specific number of zero bits. Difficulty is calculated dynamically using linear interpolation based on the request's suspicion factor.

#### Combined CPU + Memory Challenge (Level 2)
* **Target**: Medium to high suspicion.
* **Principle**: Forces the client to allocate and manipulate large RAM buffers (up to 48 MB). * *Why?* The hardware architectures used to run bot farms in parallel (massive multi-threading, low-cost virtual servers) share very limited memory resources. Making a challenge memory-intensive destroys the economic viability of brute-force attacks or large-scale scraping, while remaining transparent to a legitimate human user on a modern browser.

#### Optimization Challenge & Useful Work (Level 3 - Advanced)
* **Target**: High suspicion level (just below the blocking threshold).
* **Principle**: Requires solving a complex NP-complete problem (such as the Traveling Salesperson Problem - TSP) or a useful distributed computation configured by the server. This demands extreme computational effort or logical interaction that cannot be faked without stalling the execution agent for several seconds.

---

## Challenge Validation and Security

To prevent any circumvention, the challenge lifecycle is highly secure:

1. **Cryptographic Challenge Binding**: The generated challenge (`baseBlock`) cryptographically incorporates the nonce, the device fingerprint (`x-device-fingerprint`), and the IP address.
2. **Context Signing**: The challenge context is signed using an HMAC on the server before being stored in the database. Any physical or logical tampering with the in-memory session—attempting to simplify the challenge—will invalidate the signature.
3. **Fingerprint Consistency Check upon Return**: When the response is submitted, the server compares the fingerprint of the machine that solved the problem with that of the machine that initiated the request. If the fingerprints differ (indicating the challenge was offloaded and solved on a different machine or an external decoding server), access is immediately denied. 4. **Temporal Access Ticket** : Once the challenge is successfully completed, the server issues a single-use opaque token or a temporary secure cookie with a Time-to-Live (TTL) adaptively optimized by a background **Pareto Genetic Algorithm**, adjusted based on the device's risk level.