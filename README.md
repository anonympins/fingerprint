# Fingerprint Anti-Bot Protection: Secure Your Digital Assets

NodeJS tests : [![https://github.com/anonympins/fingerprint/actions/workflows/ci-nodejs.yml](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-nodejs.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-nodejs.yml) / PHP tests : [![https://github.com/anonympins/fingerprint/actions/workflows/ci-php.yml](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-php.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-php.yml) / Python tests : [![https://github.com/anonympins/fingerprint/actions/workflows/ci-python.yml](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-python.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-python.yml) / Java tests : [![https://github.com/anonympins/fingerprint/actions/workflows/ci-java.yml](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-java.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-java.yml)

[![https://github.com/anonympins/fingerprint/releases/tag/fingerprint-0.5.0](https://img.shields.io/github/v/release/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/releases)
[![https://raw.githubusercontent.com/anonympins/fingerprint/refs/heads/main/LICENSE](https://img.shields.io/github/license/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/blob/main/LICENSE)
[![https://img.shields.io/npm/dw/%40anonympins%2Ffingerprint](https://img.shields.io/npm/dw/%40anonympins%2Ffingerprint)](https://img.shields.io/npm/dw/%40anonympins%2Ffingerprint)
[![https://github.com/anonympins/fingerprint](https://img.shields.io/github/repo-size/anonympins/fingerprint)](https://github.com/anonympins/fingerprint)

A multi-layered behavioral, cryptographic, and network analysis production-grade engine designed to identify and mitigate malicious requests (bots, scrapers, session hijacking, bot farms) in real-time. Supports **Node.js**, **Java**, **Python** and **PHP** environments.

It leverages multi-layer hardware fingerprinting, real-time behavioral analysis, passive network/TLS tracking, and adaptive/useful proof-of-work challenges to dynamically detect and mitigate scraping, scalping, account takeover (ATO), and sophisticated automated threats.

Supported officially on **Node.js (>=20.0.0)**, **PHP (>=8.0)**, Java (>=17), and **Python (>=3.8)**.

![illustration](https://i.ibb.co/fV1QT6Mf/image-c6e10859baae53bb595112ec08fc9e27.png)

### Presentation video

[![Presentation](https://i.ibb.co/1tkPS01C/Capture-d-cran-2026-09-07-194728.png)](https://www.youtube.com/watch?v=Ujeznl0JAl4)


## 🚀 Key Features: Stop Automated Threats and Protect Your Business

### 1. 🧬 Polymorphic Client-Side WASM & JS Solvers: Outsmart Bot Adaptation
*   **Problem**: Sophisticated bots constantly adapt to your defenses, reverse-engineering client-side code to bypass protection.
*   **Solution**: Our engine dynamically generates unique, randomized client-side code (WebAssembly and JavaScript) for each session. This makes it impossible for bots to fingerprint and consistently bypass your protection, forcing them to constantly re-adapt.
*   **Benefit**: Stay one step ahead of bot developers. Your defenses evolve with every request, making automated attacks economically unviable.

### 2. 💱 Useful Proof-of-Work (uPoW) & PoSpace: Eliminate Bot Farm Profitability
*   **Problem**: Traditional CAPTCHAs and simple PoW puzzles are easily automated or solved by bot farms, leading to high operational costs for you and low costs for attackers.
*   **Solution**: We force suspicious clients to solve complex, real-world optimization problems (e.g., Traveling Salesperson, Fraud Detection parameter tuning) or prove significant storage allocation. This work is valuable to you, and computationally expensive for bot farms.
*   **Benefit**: Turn bot activity into a resource drain for attackers. By making large-scale automated attacks economically unviable, you protect your resources and ensure fair access for legitimate users.

### 3. 🌐 Passive Network Signature Analysis: Unmask Stealthy Bots
*   **Problem**: Advanced bots try to mimic real browsers, but often fail to replicate genuine network signatures, allowing them to slip past basic defenses.
*   **Solution**: Our engine analyzes deep network layers (TLS, HTTP/2, TCP/IP stack) to identify unique digital fingerprints. This includes inspecting TLS handshake details (JA3/JA4), HTTP/2 settings, and even raw TCP packet characteristics (like TTL and Window Size) to classify the true nature of the client.
*   **Benefit**: Detect and block bots that attempt to spoof their identity at the transport layer, revealing their true automated nature regardless of their declared User-Agent.

### 4. 🧠 Stateful Behavioral Entropy & Click Variance: Distinguish Humans from Robots
*   **Problem**: Bots can simulate basic interactions, but they lack the subtle, natural imperfections of human behavior, making them hard to differentiate from real users.
*   **Solution**: We analyze real-time user interactions, including mouse movements (speed, acceleration, straightness), typing rhythm (keystroke latency, dwell, and flight times), and click precision (coordinate variance). These metrics reveal whether an interaction is genuinely human or robotically precise.
*   **Benefit**: Identify and block sophisticated bots that attempt to mimic human behavior, protecting your applications from automated fraud, account takeovers, and content manipulation.

### 5. 🔍 Cross-Layer & Analog Inconsistency Scoring: Expose Advanced Spoofing
*   **Problem**: Bots often try to fake their identity across different layers of their connection, leading to inconsistencies that traditional security systems miss.
*   **Solution**: Our engine cross-references information from various layers (User-Agent, Client Hints, TLS, TCP stack) to detect subtle discrepancies. For example, a client claiming to be a Windows browser but exhibiting a Linux TCP stack will be flagged.
*   **Benefit**: Catch advanced spoofing attempts that bypass single-layer detection, providing a more robust defense against sophisticated attackers.

### 6. 🌐 Federated Threat Intelligence & Peer Sharing: Immunize Your Network Instantly
*   **Problem**: Isolated servers are vulnerable to distributed attacks, learning about new malicious actors only after being hit and compromised.
*   **Solution**: Our decentralized gossip protocol securely synchronizes cryptographically signed, privacy-compliant threat intelligence (ZKP public keys) with trusted peer networks in real-time. If an attacker is blocked on one federated node, they are instantly blacklisted across all nodes.
*   **Benefit**: Leverage collective defense. Your system is immunized against active botnets before they even attempt to target your servers.

### 7. 🕸️ Coordinated Botnet Clustering: Neutralize IP-Rotation Tactics
*   **Problem**: Modern botnets rotate thousands of clean, residential proxy IPs to easily bypass traditional IP-based reputation lists and standard rate limiters.
*   **Solution**: The engine clusters and profiles incoming requests using highly stable, non-volatile hardware invariants (such as combinations of JA3/JA4, TCP, and GPU hashes). Multiple requests sharing the exact same hardware footprint across distinct IPs within a rolling window are grouped and treated as a single coordinated botnet.
*   **Benefit**: Defeat distributed scraping and credential stuffing campaigns, making expensive residential proxy rotation completely useless for attackers.

### 8. 🦠 Honeypot Traps & Extensible WAF: Instantly Condemn Malicious Actors
*   **Problem**: Malicious bots and vulnerability scanners often probe for hidden fields or sensitive URLs, but traditional defenses only react after an attack has occurred.
*   **Solution**: We deploy invisible traps (hidden form fields, signed trap URLs) that only bots interact with. Any interaction with these honeypots immediately triggers a maximum suspicion score, leading to instant blocking. Our extensible WAF also detects common injection attempts (SQLi, XSS, RCE).
*   **Benefit**: Proactively identify and block malicious actors at the earliest stage of their attack, preventing data breaches, spam, and system exploitation.
### 9. 🧬 Progressive Threshold Auto-Tuning: Adapt Your Defenses Automatically
*   **Problem**: Threat landscapes constantly evolve, requiring continuous manual adjustments to security settings, which is time-consuming and prone to human error.
*   **Solution**: Our engine uses a genetic algorithm to continuously optimize your security parameters (weights, thresholds, patterns) in the background, based on real-world traffic data. It learns to distinguish between legitimate users and bots, adapting your defenses in real-time.
*   **Benefit**: Maintain optimal protection without constant manual intervention. Your security posture automatically adapts to new threats and traffic patterns, ensuring maximum effectiveness and minimal false positives.

## Quick Start

### Node.js

```bash
npm install @anonympins/fingerprint
```

### PHP

```bash
composer require anonympins/fingerprint
```

### Python
```bash
pip install anonympins-fingerprint
```

### Java
In your **pom.xml**, add :
```xml
<dependency>
    <groupId>com.anonympins</groupId>
    <artifactId>fingerprint-engine</artifactId>
    <version>0.7.1</version>
</dependency>
```
## Documentation

To prevent documentation drift, all detailed guides and reference materials are maintained in the `doc/` directory. Please refer to [these resources](https://github.com/anonympins/fingerprint/wiki/home) to configure and integrate the engine:

1. **[Key Concepts & Suspicion Vectors](https://github.com/anonympins/fingerprint/wiki/concepts)**: Learn how the engine calculates suspicion scores across the 15 distinct vectors and manages the Proof-of-Work mitigation layers.
2. **[Node.js Integration Guide](https://github.com/anonympins/fingerprint/wiki/nodejs_integration)**: Step-by-step instructions for Express.js middleware and raw HTTP server integrations.
3. **[PHP Integration Guide](https://github.com/anonympins/fingerprint/wiki/php_integration)**: Configuration details for direct PHP integration, TLS fingerprinting forwarding via Nginx/Apache, and securing Prometheus metrics.
4. **[Python Integration Guide](https://github.com/anonympins/fingerprint/wiki/python_integration)**: Python middleware for ASGI and WSGI integration.
5. **[Java Integration Guide](https://github.com/anonympins/fingerprint/wiki/java_integration)**: Java library (Servlet, Spring WebFlux)
6. **[Full Configuration Options](https://github.com/anonympins/fingerprint/wiki/full_options)**: Complete parameter list for fine-tuning weights, custom honeypots, and security profile overrides.
7. **[API Reference](https://github.com/anonympins/fingerprint/wiki/api_reference)**: Public API signatures and guides on substituting the in-memory datastore with Redis or MongoDB.

Start with the **[Documentation Portal](https://github.com/anonympins/fingerprint/wiki/home)** for a complete index.

## Contributing

We welcome community contributions! Please read our **[Contributing Guidelines](https://github.com/anonympins/fingerprint/blob/main/CONTRIBUTING.md)** for information on:
- Setting up your local environment (Node.js and PHP).
- Running the test suites (`Vitest` and `PHPUnit`).
- Coding and pull request standards.

Thanks to our contributors : 
- [anonympins](https://github.com/anonympins)

## 💖 Sponsor This Project

If this security suite helps protect your business against botnets, automated scraping, credential stuffing, or Layer 7 DDoS attacks, please consider supporting its active development!

Sponsorship helps maintain the library, fund active updates, and keep the dynamic WebAssembly engine cutting-edge.

**Want to be featured here?** You can also become a sponsor and get your logo displayed in this section simply by running Fingerprint in production on your platforms!

### 🌟 Featured Sponsors

<img src="https://s6.imgcdn.dev/YJTWv9.png" width="100" alt="YJTWv9.png" border="0" valign="middle"> 

[https://primals.net](https://primals.net) and sub-sites


## License

This project is licensed under the MIT License.