# Documentation - Fingerprint Protection Engine

Welcome to the official documentation for the fingerprinting and protection library. This engine provides multi-layered behavioral, cryptographic, and network analysis to identify and mitigate malicious requests (bots, scrapers, session hijacking) in real-time.

---

## Table of Contents

### 1. [Key Concepts and Suspicion Vectors](concepts)
Understand the internal workings of the detection engine and how suspicion scores are calculated.
* **Multi-layered decision architecture**: TLS, protocol, network, global identity, and behavior.
* **The 15 suspicion vectors explained**:
* Scores for rotation, IP history, header anomalies, TLS fingerprints (JA3/JA4), etc.
* Behavioral analysis (mouse movements, keystrokes, click variance).
* **Remediation mechanisms (PoW)**:
* Standard CPU challenge (Level 1).
* Combined CPU + Memory challenge against bot farms (Level 2).
* Optimization challenge and useful work (Level 3).

### 2. [PHP Integration Guide](php_integration)
Learn how to protect your PHP applications, ranging from direct integration to web server configurations.
* **Prerequisites**: PHP 8.0+, BCMath and GMP extensions.
* **Basic direct integration**: Instant protection via `DirectFingerprint`.
* **TLS Fingerprinting (JA3/JA4)**: Detailed configuration for **Nginx** (via `ngx_http_ssl_ja3_module`) and **Apache** (via `mod_ssl_ja3`).
* **Prometheus metrics**: Exposing and securing the metrics endpoint.

### 3. [Node.js Integration Guide](nodejs_integration)
Integrate protection into your server-side JavaScript applications. * **Prerequisites**: Handling of cookies and request bodies.
* **Express.js Middleware**: Quick and easy usage with `powMiddleware`.
* **Raw HTTP Integration**: Manual use of the engine for other frameworks (Koa, Fastify, native HTTP).

### 4. [Full Configuration Options](full_options)
Find the comprehensive list of all available configuration properties to fine-tune your security.
* **Complete PHP configuration example** (associative array).
* **Complete Node.js configuration example** (JS object).
* **Predefined security profiles**:
* `balanced`: Standard; balances UX and security.
* `strict`: High security; mandatory challenges for new devices.
* `api`: Focused on rate-limiting and API scraping.
* `blog`: Human-friendly; protects against spam and content scraping.
* `ecommerce`: Protects against account takeover and scalper bots.

### 5. [API Reference](api_reference)
Review public method signatures and persistent storage system configurations.
* **Node.js Public API**: `powMiddleware`, `identifyRequest`, `createSecurityProfile`, and `FingerprintBuilder`.
* **PHP Public API**: `DirectFingerprint`, `SecurityProfiles`, and `StoreManager`.
* **Datastore Configuration**: Replacing in-memory storage with external databases (examples using **MongoDB** and **Redis**).

---

*To contribute to the project or run the test suite (Vitest / PHPUnit), please consult the CONTRIBUTING.md file in the project root.*