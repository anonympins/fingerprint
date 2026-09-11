# Fingerprint anti-bot protection

NodeJS tests : [![Test NodeJS](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-nodejs.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci.yml) / PHP tests : [![PHP](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-php.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-php.yml) / Python tests : [![PHP](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-php.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci-python.yml)

[![Release](https://img.shields.io/github/v/release/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/releases)
[![License](https://img.shields.io/github/license/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/blob/main/LICENSE)
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/anonympins/fingerprint)
![Repo size](https://img.shields.io/github/repo-size/anonympins/fingerprint)

A multi-layered behavioral, cryptographic, and network analysis production-grade engine designed to identify and mitigate malicious requests (bots, scrapers, session hijacking, bot farms) in real-time. Supports **Node.js**, **Python** and **PHP** environments. 

It leverages multi-layer hardware fingerprinting, real-time behavioral analysis, passive network/TLS tracking, and adaptive/useful proof-of-work challenges to dynamically detect and mitigate scraping, scalping, account takeover (ATO), and sophisticated automated threats.

Supported officially on **Node.js (>=20.0.0)**, **PHP (>=8.0)**, and **Python (>=3.8)**.

![illustration](https://i.ibb.co/fV1QT6Mf/image-c6e10859baae53bb595112ec08fc9e27.png)

### Presentation video

[![Presentation](https://i.ibb.co/1tkPS01C/Capture-d-cran-2026-09-07-194728.png)](https://www.youtube.com/watch?v=Ujeznl0JAl4)


## 🚀 Key Features

### 1. 🧬 Polymorphic Client-Side WASM & JS Solvers
* **Polymorphic WebAssembly Solver**: Dynamically generates unique, randomized C++ compiled WebAssembly binary modules per session. Prevents static analysis, bot automation, and emulator tampering.
* **IndexedDB WASM Caching**: Transparently caches compiled WASM modules (`wasm-cache-db`) in the browser's IndexedDB, minimizing initialization overhead and execution lag on subsequent visits.
* **Advanced Obfuscation**: Uses multi-layered control flow flattening and string array obfuscation for client-side libraries.

### 2. 💱 Useful Proof-of-Work (uPoW) & PoSpace
* **Collaborative Useful PoW**: Instead of burning CPU cycles on arbitrary mathematical hash puzzles, suspicious clients solve complex optimization problems (e.g., *Traveling Salesperson*, *Portfolio Allocation*, *Facility Location*, *Fraud Detection Parameter Tuning*).
* **Proof-of-Space (PoSpace) Challenge**: Forces browser clients to allocate and verify access to massive, persistent storage chunks (e.g., 100MB) inside IndexedDB, multiplying the cost of multi-threaded headless automation.
* **Chained CPU/Memory Challenges**: Employs client-side resource exhaustion techniques (Chained SHA-256 target seeking & Memory Hard allocation vectors up to 128MB) that are validated in $O(1)$ on the server.

### 3. 🌐 Passive TLS, HTTP/2, and TCP/IP (p0f) Tracking
* **Native JA3/JA4 TLS Handshake Parsing**: Inspects raw TLS client hello bytes to extract and analyze cipher suite arrangements, extensions, and elliptic curve formats.
* **Passive TCP/IP Stack Fingerprinting**: Emulates `p0f` rules by analyzing raw TCP SYN packets (TTL, Window Size, MSS, WS, SACK) to classify client OS and detect raw network spoofing.
* **Multi-Language Handshake Parser**: Built-in support for event-driven PHP runtimes (Swoole, ReactPHP, Workerman), Node.js native sockets, and Python ASGI/WSGI contexts.

### 4. 🧠 Stateful Behavioral Entropy & Click Variance
* **Click Coordinate Variance**: Tracks exact click relative positions on DOM elements to compute spatial entropy, flagging bots clicking targets with robotic, mathematically perfect precision (zero variance).
* **Mobile Touch Move Dynamics**: Captures mobile-specific touchscreen signals, analyzing tactile contact area radius, variable pressure indices, and multi-touch capabilities.
* **Typing Keystroke Latency**: Measures real-time keystroke interval latencies to prevent automated text insertion.

### 5. 🔍 Cross-Layer & Analog Inconsistency Scoring
* **Layer Cross-Referencing**: Analyzes inconsistencies between User-Agent declarations, Client-Hints (`Sec-CH-UA`), TLS Handshake capabilities, and TCP stacks (e.g., claiming Windows NT on Chrome but negotiating TLS like curl/Safari on a Linux kernel).
* **Viewport Aspect ratio & Screen mismatches**: Detects virtualized viewports exceeding physical dimensions or fake hardware specifications.

### 6. 🦠 Honeypot Traps & Extensible WAF
* **Signed Trap URLs**: Injects visually hidden, signed trap URLs into the DOM. Attempts to crawl, probe, or scrape these URLs immediately condemn the device.
* **Recursive Injection Filters**: Inspects deeply nested payload structures (JSON/NoSQL/GraphQL) using a robust regular expression matrix to flag SQLi, XSS, XXE, SSTI, and JNDI (Log4Shell) vulnerabilities.
* **ModSecurity NodeJS Extensibility**: Allows plugging in native core rule sets or custom WAF rule compilers into the honeypot pipeline.

### 🧬 Progressive Threshold Auto-Tuning
* **Genetic Policy Optimizer**: Dynamically updates classification parameters using a multi-objective genetic algorithm on your actual sanitized traffic data.
* **Inertial Parameter Sliding**: Adjusts security thresholds slowly with an adaptive learning rate to prevent configuration spikes.
* **Sybil Protection**: Filters out traffic logs, ensuring individual compromised bot networks cannot pollute optimization datasets.

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
pip install fingerprint-engine
```

## Documentation

To prevent documentation drift, all detailed guides and reference materials are maintained in the `doc/` directory. Please refer to [these resources](https://github.com/anonympins/fingerprint/wiki/home) to configure and integrate the engine:

1. **[Key Concepts & Suspicion Vectors](https://github.com/anonympins/fingerprint/wiki/concepts)**: Learn how the engine calculates suspicion scores across the 15 distinct vectors and manages the Proof-of-Work mitigation layers.
2. **[Node.js Integration Guide](https://github.com/anonympins/fingerprint/wiki/nodejs_integration)**: Step-by-step instructions for Express.js middleware and raw HTTP server integrations.
3. **[PHP Integration Guide](https://github.com/anonympins/fingerprint/wiki/php_integration)**: Configuration details for direct PHP integration, TLS fingerprinting forwarding via Nginx/Apache, and securing Prometheus metrics.
3. **[Python Integration Guide](https://github.com/anonympins/fingerprint/wiki/python_integration)**: Python middleware for ASGI and WSGI integration.
4. **[Full Configuration Options](https://github.com/anonympins/fingerprint/wiki/full_options)**: Complete parameter list for fine-tuning weights, custom honeypots, and security profile overrides.
5. **[API Reference](https://github.com/anonympins/fingerprint/wiki/api_reference)**: Public API signatures and guides on substituting the in-memory datastore with Redis or MongoDB.

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

### 🌟 Featured Sponsors

- ![](https://primals.net/PRIOR.png) https://primals.net and sub-sites
  <img src="https://s6.imgcdn.dev/YJTWv9.png" width="100" alt="YJTWv9.png" border="0">

## License

This project is licensed under the MIT License.