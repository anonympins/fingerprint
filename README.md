# Fingerprint anti-bot protection

NodeJS tests : [![Test NodeJS](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-nodejs.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci.yml)

PHP tests : [![PHP](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci-php.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci.yml)

[![Release](https://img.shields.io/github/v/release/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/releases)
[![License](https://img.shields.io/github/license/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/blob/main/LICENSE)
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/anonympins/fingerprint)

A multi-layered behavioral, cryptographic, and network analysis engine designed to identify and mitigate malicious requests (bots, scrapers, session hijacking) in real-time. Supports both **Node.js** and **PHP** environments.

## Key Features

- **Multi-Layered Detection**: Combines TLS/JA3/JA4 analysis, HTTP header consistency checks, IP reputation, and behavioral tracking (mouse movements, keystrokes).
- **Adaptive Mitigation**: Imposes progressive cryptographic Proof-of-Work (PoW) challenges to block automated clients without impacting legitimate human users.
- **Predefined Profiles**: Ready-to-use security profiles (`balanced`, `strict`, `api`, `blog`, `ecommerce`) tailored to your specific use case.

## Quick Start

### Node.js

```bash
npm install @anonympins/fingerprint
```

### PHP

```bash
composer require anonympins/fingerprint
```

## Documentation

To prevent documentation drift, all detailed guides and reference materials are maintained in the `doc/` directory. Please refer to [these resources](home) to configure and integrate the engine:

1. **[Key Concepts & Suspicion Vectors](https://github.com/anonympins/fingerprint/wiki/concepts)**: Learn how the engine calculates suspicion scores across the 15 distinct vectors and manages the Proof-of-Work mitigation layers.
2. **[Node.js Integration Guide](https://github.com/anonympins/fingerprint/wiki/nodejs_integration)**: Step-by-step instructions for Express.js middleware and raw HTTP server integrations.
3. **[PHP Integration Guide](https://github.com/anonympins/fingerprint/wiki/php_integration)**: Configuration details for direct PHP integration, TLS fingerprinting forwarding via Nginx/Apache, and securing Prometheus metrics.
4. **[Full Configuration Options](https://github.com/anonympins/fingerprint/wiki/full_options)**: Complete parameter list for fine-tuning weights, custom honeypots, and security profile overrides.
5. **[API Reference](https://github.com/anonympins/fingerprint/wiki/api_reference)**: Public API signatures and guides on substituting the in-memory datastore with Redis or MongoDB.

Start with the **[Documentation Portal](home)** for a complete index.

## Contributing

We welcome community contributions! Please read our **[Contributing Guidelines](https://github.com/anonympins/fingerprint/blob/main/CONTRIBUTING.md)** for information on:
- Setting up your local environment (Node.js and PHP).
- Running the test suites (`Vitest` and `PHPUnit`).
- Coding and pull request standards.

## License

This project is licensed under the MIT License.