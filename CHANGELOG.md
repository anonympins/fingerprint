## Version 0.3.1

This release marks a major expansion of the library, introducing a full-featured PHP version that mirrors the capabilities of the Node.js module. It also adds GraphQL operation whitelisting and an obfuscated client build for enhanced security.

### ✨ New Features

*   **Full PHP Support**: The library is now available for PHP 7.4+ with a feature set equivalent to the Node.js version.
    *   **Direct Integration**: A `DirectFingerprint` class allows for easy integration into any PHP application, including legacy codebases, by interacting directly with PHP's superglobals.
    *   **PSR-15 Middleware**: A `FingerprintMiddleware` is provided for modern, framework-agnostic integration with applications that follow PSR-7, PSR-15, and PSR-17 standards (e.g., Slim, Laminas).
    *   **Pluggable Datastores**: The PHP version supports the same pluggable store architecture, allowing state to be persisted in Redis, databases, or other external systems.
    *   **Security Profiles**: The same pre-configured security profiles (`balanced`, `strict`, `api`, etc.) are available in PHP via `SecurityProfiles::createSecurityProfile()`.
    *   **Client-Side Helper**: A `FingerprintClient` class is included to simplify the injection of the client-side JavaScript library and honeypot fields into PHP-rendered HTML pages.

*   **GraphQL Whitelisting**: You can now whitelist specific GraphQL operations to bypass security checks. This is ideal for allowing public queries (like `GetPublicPosts`) while protecting sensitive mutations. This is supported in both Node.js and PHP.
    *   Example rule: `{ type: 'graphql_operation_allowlist', entries: ['query:GetPublicPosts', 'mutation:*'] }`

### 🚀 Improvements

*   **Obfuscated Client Script**: The build process now generates an obfuscated version of the client-side JavaScript library (`fingerprint.client.obfuscated.js`). This makes it significantly more difficult for attackers to reverse-engineer the client-side fingerprinting and behavioral analysis logic.
*   **Expanded PHP Test Coverage**: The new PHP module includes a comprehensive suite of PHPUnit tests, ensuring the reliability and correctness of the `FingerprintEngine`, challenge verification, and scoring logic.
*   **Unified Documentation**: The `README.md` has been updated with dedicated sections and quick-start guides for both Node.js and the new PHP integrations, providing clear instructions for both platforms.

### 📦 Build & Internals

*   The project structure now includes a `src/php` directory containing the full PHP library implementation.
*   A `phpunit.xml` configuration has been added to manage the PHP test suite.

## Version 0.3.0 

This is a major release focused on security hardening, distributed system capabilities, and overall robustness. It introduces advanced TLS spoofing detection, protection against various resource exhaustion and data poisoning attacks, and makes the "Useful Proof-of-Work" system truly scalable.

### 🔒 Security Enhancements

*   **Advanced TLS Spoofing Detection**: The engine now performs a much deeper analysis to detect when a client is faking its identity. It cross-references the TLS JA3 fingerprint against an internal database of known browser and library signatures. A request with a `User-Agent` for Chrome but a JA3 fingerprint for a Python `requests` library will now be heavily penalized.
*   **uPoW Resource Drain Protection**: Implemented a hard cap on the difficulty of "Useful Proof-of-Work" (uPoW) tasks. This prevents a malicious client from being assigned a computationally impossible task that could drain server resources during verification.
*   **Memory PoW DoS Protection**: A hard cap has been added to the memory allocation size for the memory-based PoW challenge, preventing a malicious client from forcing the server to allocate excessive amounts of memory.
*   **Auto-Tuner Data Poisoning Protection**: The auto-tuner is now more robust against data poisoning attacks. It better distinguishes between legitimate traffic patterns and malicious attempts to skew its learning process, ensuring the optimized parameters remain effective.
*   **Invalid Nonce Protection**: The challenge-response mechanism is now hardened. Any attempt to submit a solution for an invalid or expired nonce is immediately flagged as a high-risk honeypot interaction, resulting in a block or a maximum-difficulty challenge.
*   **Cryptographically Secure Randomness**: The internal library now uses `crypto.randomBytes` instead of `Math.random` for all security-sensitive operations, ensuring higher quality randomness for tasks like genetic algorithm mutations and selection.

### ✨ New Features

*   **Distributed uPoW State**: The state of "Useful Proof-of-Work" problems (e.g., the best solution found for a TSP problem) is now persisted through the configured datastore (e.g., Redis, MongoDB). This allows a cluster of server instances to collaborate on solving the same complex problems, making the system truly distributed and more powerful.

### 🚀 Improvements

*   **Smarter Fingerprint Comparison**: The `FingerprintBuilder.compare()` method is now more precise. It applies a penalty for unknown or missing keys in a fingerprint, making it better at detecting subtle differences between a legitimate user and an attacker attempting to mimic a fingerprint.
*   **Configuration Validation**: The engine now checks for unknown keys in the `securityConfig` object upon initialization and will log a warning. This helps developers quickly identify typos or misconfigurations.
*   **Asynchronous Problem Loading**: The `problems.config.json` file is now read asynchronously and debounced at startup, improving application start time and preventing race conditions.
*   **Optional Peer Dependencies**: The `package.json` has been updated to mark datastore drivers (`ioredis`, `mongodb`, `knex`, `sqlite3`) as optional `peerDependencies`. This provides a cleaner installation for users who do not need a specific external store.

## Version 0.2.3

This release introduces major improvements in ease of use and flexibility. It adds pre-configured security profiles for rapid setup, more granular whitelisting controls, and expands the "Useful Proof-of-Work" system with a new range of complex optimization problems.

### ✨ New Features

*   **Security Profiles & Quick Init**:
    *   To simplify setup, you can now use the `createSecurityProfile()` helper to load pre-configured profiles tailored for common use cases: `balanced` (default), `strict`, `api`, `blog`, and `ecommerce`.
    *   These profiles provide a solid starting point and can be easily customized with your own overrides.

*   **Advanced Whitelisting Controls**:
    *   **`path_allowlist`**: A new whitelisting rule to bypass checks for specific URL paths. It's perfect for public API endpoints, webhooks, or static content that doesn't require protection. Supports wildcards (e.g., `/api/public/*`).
    *   **`host_path_allowlist`**: Provides even more granular control by whitelisting a path only when it's on a specific host. This is ideal for multi-tenant applications or for securing an API on one domain but not another (e.g., `api.example.com/v1/webhooks/*`).

*   **Expanded Useful Proof-of-Work (uPoW) Problems**:
    *   The `ProblemManager` is now more powerful, with support for a wider range of real-world optimization tasks that can be offloaded to suspicious clients.
    *   The `problems.config.json` has been updated with new examples, including:
        *   **Fraud Detection Tuning**: Finding optimal thresholds for fraud detection systems.
        *   **Facility Location**: Solving complex logistical placement problems.
        *   **Security Auto-Tuning**: Using client CPU to dynamically optimize the library's own security parameters.
        *   **CPC Optimization**: Finding optimal Cost-Per-Click values in a simulated ad-tech environment.
    *   The `FunctionRegistry` in `problem-manager.js` has been updated to support these new problem types.

### 🚀 Improvements

*   **Documentation**: The `README.md` has been updated to reflect the new security profiles and whitelisting options, with clear examples for each.


## Version 0.2.2 

This version marks a significant evolution from simple Proof-of-Work (PoW) to "Useful Proof-of-Work" (uPoW). Instead of solving arbitrary computational puzzles, clients now contribute to solving complex optimization problems, making the work done to verify a client's legitimacy valuable.

### ✨ New Features

*   **Useful Proof-of-Work (uPoW) System**:
    *   Introduced the `ProblemManager` to oversee long-running optimization problems (e.g., Traveling Salesperson Problem, Portfolio Optimization).
    *   Clients' PoW challenges now consist of running optimization algorithms (like Simulated Annealing or Genetic Algorithms) for a specific number of iterations/generations.
    *   Solutions submitted by clients are integrated back into the system, continuously improving the best-known solution for each problem over time.

*   **Dynamic Problem Configuration**:
    *   The `problems.config.json` file now supports dynamic data generation. You can specify functions like `generate:randomPoints` or `generate:randomAssets` to create new problem instances on startup without manual data entry.

*   **Best Solution API**:
    *   A new method, `fingerprint.getBestSolutions(problemId?)`, has been added. This allows you to retrieve the best solution found so far for a specific problem or for all active problems. This makes the results of the uPoW system accessible and useful.

*   **Re-challenge for High-Suspicion Clients**:
    *   Clients with a very high `suspicionFactor` are now automatically issued a second challenge upon successful completion of the first. This significantly increases the cost of verification for highly suspicious actors without affecting legitimate users.


### 🚀 Improvements

*   **Smarter Challenge Difficulty**:
    *   The difficulty of optimization challenges now scales more intelligently with the client's `suspicionFactor`.
    *   A minimum difficulty has been established for challenges to ensure they are always meaningful, preventing trivial PoW tasks even for low-suspicion clients.
    *   Added a linear "decay" mode as an alternative to exponential scaling. If a `scalingFactor` is not defined for a problem, the difficulty increases linearly, providing a gentler curve for low-suspicion clients.

*   **Data Point Capping**:
    *   Added a `maxDataPoints` option to problem configurations to prevent datasets (e.g., TSP points) from growing indefinitely. This ensures stable performance and memory usage over time. (Thanks, @anonympins!)
*   **Enhanced Test Suite**:
    *   Added comprehensive unit tests for the new `ProblemManager`, ensuring the reliability of problem loading, work dispatching, solution integration, and the new dynamic configuration features.

### Internal & Developer Experience

*   The core logic for managing, dispatching, and updating optimization problems is now encapsulated within `problem-manager.js`.
*   The project now uses `vitest` for running tests, as configured in `package.json`.