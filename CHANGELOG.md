## Version 0.3.3

This release introduces significant enhancements to client-side behavioral analysis, adds a crucial "dry run" mode for safe production testing, and improves the overall developer experience with an event-driven client library and better packaging.

### ✨ New Features

*   **Advanced Behavioral Analysis: Click Variance**:
    *   The client-side library now tracks the exact coordinates of user clicks on interactive elements.
    *   A new `clickVarianceScore` is calculated on the server-side (for both PHP and Node.js) to penalize unnaturally precise, bot-like clicking patterns (e.g., always hitting the exact same pixel). This adds a powerful new dimension to detecting sophisticated automation.

*   **"Dry Run" Mode**:
    *   A `dryRun: true` option can now be added to the security configuration. When enabled, the engine performs all calculations and logs the action it *would* have taken (`block`, `challenge`) but never actually interrupts the request.
    *   This is invaluable for safely testing new or stricter configurations in a live production environment without affecting real users.

*   **Client-Side Event Emitter**:
    *   The client library now emits events for key actions (e.g., `challenge_issued`, `challenge_solved`, `honeypot_triggered`). This allows developers to easily hook into the library's lifecycle to trigger custom UI changes, analytics, or logging.

### 🚀 Improvements

*   **Enhanced Mouse Tracking Analysis**: The server-side analysis of mouse movement data has been refined to better distinguish between natural, human-like cursor paths and the linear or predictable movements typical of bots.
*   **PHP Code Quality**: The entire PHP codebase has undergone a syntax normalization pass, improving consistency and long-term maintainability.
*   **Test Suite Reliability**:
    *   Unit tests for the client-side `initializeClient` function have been added and improved.
    *   New unit tests cover the "Dry Run" mode functionality.
    *   Fixed existing unit tests for the `ProblemManager` to ensure the stability of the Useful-Proof-of-Work system.

### 📦 Build & Internals

*   **Corrected NPM Package Files**: The `files` array in `package.json` has been updated to ensure all necessary JavaScript source files (`library.js`, `fingerprint.builder.js`, etc.) are correctly included in the published package, fixing potential `import` issues for users.
*   **Project Structure**: The JavaScript source files have been consolidated into the `src/js` directory for a cleaner and more organized project structure.

## Version 0.3.2

This release brings major new capabilities to both the Node.js and PHP versions of the library. Key highlights include the full implementation of the "Useful Proof-of-Work" (uPoW) system in PHP, client-side acceleration via WebAssembly (WASM), direct JA3 fingerprinting in Node.js, and significant reliability improvements to the auto-tuner.

### ✨ New Features

*   **Useful Proof-of-Work (uPoW) in PHP**: The PHP version now has full feature parity with Node.js for uPoW.
    *   The `ProblemManager` is now fully implemented in PHP, allowing it to load, manage, and dispatch complex optimization problems (e.g., TSP, Portfolio Allocation) to suspicious clients.
    *   Client solutions are integrated back into the system, enabling distributed, collaborative problem-solving.

*   **WASM-Accelerated Client**: The client-side library can now be accelerated with a WebAssembly module for high-performance hashing.
    *   The build process (`build-client.js`) now includes a step to compile the C++ hashing utility into a WASM module.
    *   The client library (`fingerprint.client.js`) can dynamically load the WASM module if available, falling back gracefully to the pure JavaScript implementation. This makes client-side fingerprinting faster and harder to tamper with.

*   **Direct JA3 Fingerprinting in Node.js**: The Node.js engine can now calculate the JA3 fingerprint directly from the raw TLS `clientHello` object. This is a major enhancement, as it removes the hard dependency on a reverse proxy (like Nginx or Cloudflare) to provide the JA3 hash, making the library more versatile and easier to deploy in various environments.

*   **Auto-Tuner Solution API**: A new `getBestTuningSolution()` function has been added to the Node.js version. This allows developers to programmatically retrieve and inspect the optimal configuration (`weights`, `thresholds`, `patterns`) found by the auto-tuner, which is useful for auditing and "FinOps".

### 🚀 Improvements

*   **Probationary Tickets in PHP**: The PHP engine now supports issuing short-lived "probationary" tickets for moderately suspicious users who solve a challenge. This forces a quicker re-evaluation, increasing security for borderline cases.
*   **Auto-Tuner Reliability**: The auto-tuning mechanism has been made more robust, with fixes to default score calculations to improve its initial learning phase and overall stability.
*   **PHP 64-Bit Compatibility**: The PHP implementation of the `cyrb53` hashing algorithm and other arithmetic operations has been improved using the `gmp` extension to ensure correct and consistent results on 64-bit systems, matching the JavaScript output.
*   **Expanded PHP Test Coverage**: The PHPUnit test suite has been significantly expanded to cover the new `ProblemManager`, uPoW logic, and other core engine features, increasing overall reliability.

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