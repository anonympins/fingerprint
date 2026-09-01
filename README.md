# fingerprint
[![CI](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci.yml)](https://github.com/anonympins/fingerprint/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/releases)
[![License](https://img.shields.io/github/license/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/blob/main/LICENSE)
![GitHub commit activity](https://img.shields.io/github/commit-activity/w/anonympins/fingerprint)
[![Watchers](https://img.shields.io/github/watchers/anonympins/fingerprint)](https://github.com/anonympins/fingerprint/watchers)

An HTTP(S) client mitigation and anti-bot protection library for both PHP and Node.js/Express, based on digital fingerprinting and dynamic Proof-of-Work (PoW) challenges.

## Installation and Usage

This library is available for both **Node.js** and **PHP**.

*   [PHP Quickstart](#php-quickstart)
*   [Node.js Quickstart](#nodejs-quickstart)

## How It Works

This system identifies and slows down bots and automated scripts by evaluating the "suspicion" level of each incoming request. Instead of outright blocking, it imposes challenges with a difficulty proportional to the suspicion score, penalizing bots without significantly impacting legitimate users.

The process unfolds in three steps:

1.  **Identification & Fingerprinting**: A unique fingerprint is generated for each device. This combines a client-side browser fingerprint, server-side request headers, and the **JA3 fingerprint** from the TLS handshake, which reliably identifies the underlying HTTP client library (e.g., Chrome vs. a Python script). A `device_id` cookie is used to track the device over time.
    *   **Advanced TLS Fingerprinting (JA4/JA4H)**: Beyond JA3, the system can leverage JA4/JA4H (if provided by a reverse proxy like Cloudflare or Akamai) for a more robust and modern TLS fingerprint, especially for HTTP/2 traffic.
    *   **HTTP/2 Fingerprinting**: Analyzes HTTP/2 specific characteristics (settings frame, priority, window update) to identify client libraries.
    *   **TCP/IP Fingerprinting**: If available (e.g., from a specialized reverse proxy), low-level TCP/IP stack characteristics (TTL, window size, options) are used for identification.
    *   A `device_id` cookie is used to track the device over time.
2.  **Suspicion Score Calculation**: Several indicators are analyzed to calculate a suspicion score:
    *   **Header Anomalies**: Missing `User-Agent`, `Accept-Language`, etc.
    *   **Device Behavior**: Rapid fingerprint changes (User-Agent rotation).
    *   **IP Behavior**: An excessive number of different devices seen from the same IP, or a single device using a large number of IPs (proxy rotation).
    *   **Inconsistency**: A low similarity score between the current fingerprint and the one initially associated with the `device_id` (cookie theft detection).
    *   **Cross-Layer Inconsistency**: Mismatches between client-side data (e.g., OS reported by the browser) and server-side headers (e.g., `User-Agent`).
    *   **Request Patterns**: Repetitive, rapid-fire, or sequential requests typical of scraping bots. The parameters for detecting these patterns (e.g., request velocity, burst detection) are dynamically adjusted by the auto-tuner for optimal performance.
    *   **Honeypot Trap**: Detection of bots that automatically fill hidden form fields or probe for common but unused URL parameters (e.g., `?debug=true`).
    *   **TLS Fingerprint Spoofing**: Detects inconsistencies between the TLS fingerprint (JA3/JA4) and other HTTP headers (e.g., User-Agent), indicating an attempt to disguise the client.
3.  **Dynamic Challenge**: If the suspicion score exceeds a certain threshold, a challenge is presented. The difficulty and type of challenge depend on the score:
    *   **Low to Medium Suspicion**: A combined **CPU and Memory Proof-of-Work (PoW)** challenge is issued. The difficulty of both the CPU (hash calculation) and Memory (allocation and computation) components scales progressively with the suspicion score. For low scores, the memory challenge is negligible, making it primarily a CPU task.
    *   **High Suspicion**: For the most suspicious requests, the system issues a high-difficulty combined CPU/Memory challenge or a "Useful Proof-of-Work" task (see below). The architecture allows for plugging in more complex challenges like CAPTCHAs if needed.
    *   **New Devices**: To increase the cost for bots that simply clear their cookies, new (unseen) devices are systematically presented with a minimal, almost imperceptible challenge on their first visit. This behavior is enabled by default in `strict` and `ecommerce` profiles and can be configured with the `challengeNewDevices` option.

Once the challenge is solved, a clearance "ticket" is issued via a secure cookie, exempting the user from new challenges. The duration of this ticket is dynamic:
- **Probationary Ticket**: If the request was moderately suspicious, a very short-lived "probationary" ticket (e.g., 30 seconds) is issued. This forces the client to be re-evaluated quickly, increasing security.
- **Optimal TTL Ticket**: For less suspicious requests, a genetic algorithm calculates the optimal ticket duration, balancing security (shorter TTL for higher risk) and user experience (longer TTL for lower risk).

For API clients, the challenge is delivered as a `404` JSON response, and the client library can automatically solve it and retry the original request.

## Features

-   **Multi-Factor Fingerprinting**: Combines client-side data (`hardwareConcurrency`, `deviceMemory`, `screen`, `canvas`, `webgl`) and server-side data (`User-Agent`, `Client-Hints`).
-   **Secure Ticket System**: Uses HMAC-SHA256 signatures to validate clearances and prevent tampering.
-   **Pluggable Datastore**: Supports external datastores like Redis for state persistence and scalability across multiple server instances.
-   **Express.js Middleware**: Easy integration into an Express application with `powMiddleware`.
-   **Timing Attack Protection**: Uses `crypto.timingSafeEqual` for secure validation of tickets and other signatures.
-   **Bot Whitelisting**: Includes a DNS-based verification mechanism to reliably identify and whitelist legitimate crawlers like Googlebot and Bingbot, preventing them from being challenged. The results are cached for optimal performance.
-   **Automatic Parameter Tuning**: Includes a genetic algorithm-based optimizer (`startThresholdAutoTuning`) that analyzes real traffic to dynamically adjust suspicion thresholds, weights, and behavioral pattern detection parameters, improving accuracy and reducing false positives over time. The tuner is hardened against data poisoning attempts.
-   **Optional WASM Acceleration**: The client-side library can be accelerated with a WebAssembly module for high-performance hashing. The build process handles this optionally, and the client gracefully falls back to a pure JavaScript implementation if WASM is unavailable.
-   **Hardened Security**: Protects against various attacks, including DoS via memory exhaustion, invalid nonce submission, and uses cryptographically secure randomness for all sensitive operations.

### Prerequisites

*   **PHP 7.4+**
*   The **BCMath** extension (`php-bcmath`) is required. It is included by default in most PHP installations.
*   **Composer** for package management.
*   The **GMP** extension (`php-gmp`) is highly recommended for performance. If not available, the library will fall back to a slower BCMath-based implementation for cryptographic operations.

---

<a id="php-quickstart"></a>

## PHP Quickstart (Direct Integration)

This guide shows the simplest way to integrate the library into any PHP application, without requiring a framework. It interacts directly with PHP's native functions and superglobals.

### Prerequisites

*   **PHP 7.4+**
*   The **BCMath** extension (`php-bcmath`) is required. It is included by default in most PHP installations.
*   **Composer** for package management.
*   The **GMP** extension (`php-gmp`) is highly recommended for performance. If not available, the library will fall back to a slower BCMath-based implementation for cryptographic operations.

### Installation

Install the main library via Composer:

```bash
composer require anonympins/fingerprint
```

### Configuration

Define a secret key for signing Proof-of-Work tickets in your environment variables or your `.env` file. This is **required** for production environments.

```bash
POW_SECRET="your_secret_key_of_at_least_32_characters"
```

### Integration Example

This example shows how to protect an application's entry point (e.g., `index.php`) by calling the `protect()` method at the very beginning of your script.

```php
<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Anonympins\Fingerprint\Config\SecurityProfiles;
use Anonympins\Fingerprint\DirectFingerprint;

// 1. Choose a security profile and customize it if necessary.
$securityConfig = SecurityProfiles::createSecurityProfile('balanced', [
    // Enable verbose mode for development
    'verbose' => true,
]);

/*
 * IMPORTANT: Unlike Node.js, standard PHP environments (like PHP-FPM) cannot directly access
 * the raw TLS handshake to compute JA3/JA4 fingerprints.
 * To enable robust TLS fingerprinting in PHP, you must use a reverse proxy (like Nginx,
 * HAProxy, or a cloud load balancer) configured to extract the fingerprint and pass it
 * to your application via an HTTP header (e.g., `X-JA3-Hash`). The library is already
 * built to consume these headers automatically.
 */

// 2. Create an instance of the DirectFingerprint protector.
$protector = new DirectFingerprint($securityConfig);

// 3. Protect the script.
// This method will analyze the request. If it's suspicious, it will
// send a challenge or block response and then call `exit()`.
// If the request is allowed, it returns the fingerprint data.
$fingerprint = $protector->protect();

// --- If the script continues, the request was allowed ---

$score = $fingerprint['score'] ?? 0;

header('Content-Type: text/html; charset=utf-8');
echo "<h1>Welcome to the protected page!</h1>";
echo "<p>Your suspicion score was: " . round($score, 2) . "</p>";

?>
```

### Full Configuration Example (PHP)

If you prefer to define the entire configuration manually instead of using a profile, you can create a `$securityConfig` array with all the parameters. All parameters are optional, but it is highly recommended to review and adjust them for your specific needs. The engine will warn you about any unknown keys in this configuration, helping you catch typos.

```php
<?php

use Anonympins\Fingerprint\Utils\DefaultWhitelist;

// Array to store traffic analysis data for the auto-tuner.
// In a real application, this could be a more robust logging system.
$trafficData = [];

// Configuration of weights and thresholds for calculating the suspicion score.
// These values should be adjusted based on traffic and expected user behavior.
$securityConfig = [
    'weights' => [
        'historyScore' => 0.3,       // Penalizes IP rotation (proxy)
        'rotationScore' => 0.5,      // Penalizes rapid fingerprint changes (user-agent, etc.)
        'headerAnomalyScore' => 0.1, // Penalizes abnormal headers (missing UA, etc.)
        'requestPatternScore' => 0.6,// Penalizes bot-like request sequences (scraping, etc.)
        'inconsistencyScore' => 0.8, // Strongly penalizes inconsistency between the current and initial fingerprint (stolen cookie)
        'behaviorScore' => 0.7,      // Penalizes non-human interactions (no mouse/keyboard activity)
        'honeypotScore' => 1.0,      // Strongly penalizes bots filling hidden form fields
        'crossLayerInconsistencyScore' => 0.4, // Penalizes mismatches between client-side data (e.g., OS) and server-side headers (e.g., User-Agent)
        'timeInconsistencyScore' => 0.9, // Strongly penalizes large time gaps between client metric collection and server reception (replay attack)
        'tlsSpoofingScore' => 0.8,     // Penalizes mismatches between the TLS fingerprint (JA3/JA4) and the User-Agent (client spoofing)
        'botScore' => 1.0,             // Penalizes explicit bot markers from the client
        'cookieDroppingScore' => 0.9,  // Penalizes clients that appear to be intentionally dropping cookies
        'threatIntelScore' => 0.4,     // Penalizes requests from known malicious IPs (proxies, Tor, etc.)
    ],
    'thresholds' => [
        'low' => 20,    // Score from which a CPU challenge is issued
        'medium' => 45, // Score for a more difficult combined CPU/Memory challenge
        'high' => 75,   // Score for a very difficult challenge
        'block' => 95,  // Score above which the request is blocked outright (HTTP 403)
    ],
    'cpu' => [
        'minDifficultyBits' => 8,
        'maxDifficultyBits' => 24,
    ],
    // (Optional) Configure the duration (in milliseconds) for various temporary data.
    'ticketMaxAge' => 3600000, // 1 hour. Duration for which a solved challenge ticket is valid.
    'challengeTtl' => 300000,  // 5 minutes. Time during which a challenge nonce is valid.
    'deviceIdCookieMaxAge' => null, // By default, it's a session cookie. Set a value in ms for a persistent cookie.
    'challengePagePath' => './path/to/your/custom-challenge-page.html', // (Optional) Path to a custom HTML template for the challenge page.
    'verbose' => ($_ENV['APP_ENV'] ?? 'production') !== 'production', // Log detailed info in development.
    'patterns' => [ // (Optional) Initial values for request pattern detection, optimized by auto-tuner if enabled.
        'historySize' => 10,          // Number of requests to keep for pattern analysis
        'minSamples' => 5,            // Minimum number of timings to collect before statistical analysis.
        'regularityThreshold' => 50,  // Standard deviation (ms) below which behavior is "too regular".
        'benfordThreshold' => 0.15,   // Benford's Law deviation threshold above which the distribution is "unnatural".
        'patternWeight' => 80,        // Strong, one-time penalty when a pattern is detected.
        'decayFactor' => 0.9,         // Factor by which the pattern score decreases over time.
        'inactivityReset' => 5000,    // Time (ms) after which the pattern score is reset.
    ],
    'honeypot' => [
        // List of field names that are traps for bots.
        'fields' => ['email_confirm', 'user_nickname', 'debug', 'test_mode', 'admin'], // (Optional)
        // List of URL paths that should never be accessed by a legitimate user.
        'trapUrls' => ['/wp-admin', '/.env', '/admin.php', '/phpmyadmin'], // (Optional)
        // Automatically detect common injection patterns. Can be a boolean or an array of specific types.
        'detectInjections' => ['sql', 'rce', 'traversal', 'xxe', 'ssti', 'log4shell'], // (Optional, default: true)
        // (Optional) Plug in external analyzers. Each must be a callable that receives request data
        // and returns `true` if a threat is detected.
        'analyzers' => [
            // Example: A custom function to detect specific keywords (e.g., for anti-spam).
            function ($data) {
                $spamKeywords = ['viagra', 'free money', 'crypto pump'];
                $dataString = strtolower(json_encode($data));
                foreach ($spamKeywords as $keyword) {
                    if (str_contains($dataString, $keyword)) {
                        return true;
                    }
                }
                return false;
            }
        ]
    ],
    // (Optional) Whitelisting configuration.
    'whitelist' => [
        // Option 1: Static IP Allowlist (IPs or CIDR ranges).
        [
            'type' => 'allowlist',
            'entries' => [
                '192.168.1.100',      // A specific internal IP
                '203.0.113.0/24',     // A partner's network range
                '2001:db8::/32',      // An IPv6 range
            ]
        ],
        // Option 2: Host + Path Allowlist (supports wildcards).
        [
            'type' => 'host_path_allowlist',
            'entries' => [
                'api.yourdomain.com/v1/webhooks/*', // All paths under /v1/webhooks on a specific host
            ]
        ],
        // Option 3: Path Allowlist (supports wildcards).
        [
            'type' => 'path_allowlist',
            'entries' => [
                '/api/v2/public-stats', // Exact path
                '/callbacks/trusted-source/*', // All paths under /callbacks/trusted-source/
            ]
        ],
        // Option 4: GraphQL Operation Allowlist (supports wildcards).
        [
            'type' => 'graphql_operation_allowlist',
            'entries' => [
                'query:GetPublicPosts', // A specific query
                'mutation:*'            // All mutations
            ]
        ],
        // Option 5: DNS-verified bots (e.g., search engine crawlers).
        // You can use the provided default list and extend it.
        ...DefaultWhitelist::getRules(), // Use the defaults
        ['userAgent' => 'MyCustomBot', 'hostnameSuffix' => '.my-bot-verifier.com'], // Add a custom bot
    ],
    // (Optional) Custom function to identify API requests. Must be a callable.
    'isApiRequest' => function (RequestContext $context) {
        return str_starts_with($context->path, '/api/') ||
               str_contains($context->getHeader('accept') ?? '', 'application/json');
    },
    // The logger is required for auto-tuning. It must be a callable.
    'logger' => function ($log) use (&$trafficData) {
        $trafficData[] = $log;
    },
    // (Optional) Configuration for the automatic threshold and pattern tuning.
    'autotuning' => [
        'trafficData' => &$trafficData, // Pass the data source by reference.
        'interval' => 1800,              // Optimization cycle every 30 minutes (in seconds for a cron job).
        'minDataPoints' => 200,
        'maxDataPoints' => 20000,
        'savePath' => './security-config.optimized.json' // (Optional) Save the best config found.
    ],
    // Enables "Useful Proof-of-Work" for suspicious activity.
    'enableUsefulWork' => true,
    // Provide either a path to a JSON file or the configuration as an array.
    'usefulWorkConfigPath' => './path/to/your/problems.config.json', // (Optional)
    // Or provide the configuration directly as an array.
    // 'usefulWorkConfig' => [ /* ... your problem definitions ... */ ]
];

```
## TLS Fingerprinting (JA3/JA4) with Nginx and Apache

Unlike Node.js, which can directly inspect the TLS handshake, a standard PHP environment (such as PHP-FPM) runs behind a web server (Nginx, Apache) that terminates the TLS connection. Consequently, the PHP script lacks direct access to the low-level information required to calculate the JA3 fingerprint.

If you want a **better protection**, the standard solution is to delegate this calculation to the front-end web server (or a reverse proxy like HAProxy) and pass the result to PHP via an HTTP header. The library is designed to automatically detect and utilize these headers.

### Automatic Detection in the Library

The PHP `RequestContext` class automatically looks for the following headers.

Once these headers are present, the `FingerprintEngine` incorporates them into the composite device fingerprint, providing the same level of robustness as the Node.js version.

---

### Configuration with Nginx

Nginx is the simplest and most common solution. It requires your Nginx instance to be compiled with the `ngx_http_ssl_ja3_module` module. Many modern Nginx builds or distribution-provided packages include it. Here is an example configuration:

```nginx
http {
    # ... other http configurations ...

    # Declare a variable to store the JA3 fingerprint. 
    # Nginx automatically populates $ssl_ja3_hash if the module is active. 
    map $ssl_ja3_hash $ja3_hash {
        default $ssl_ja3_hash; 
    }

    server {
        listen 443 ssl http2; 
        server_name yourdomain.com; 

        # ... SSL configuration (certificates, etc.) ...
        ssl_certificate /path/to/your/fullchain.pem; 
        ssl_certificate_key /path/to/your/privkey.pem; 

        location / {
            # ... your application configuration ...
            try_files $uri $uri/ /index.php?$query_string; 
        }

        location ~ \.php$ {
            include fastcgi_params; 
            fastcgi_pass unix:/var/run/php/php8.1-fpm.sock; # Adjust for your PHP version
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; 

            # Add the JA3 fingerprint as a FastCGI parameter. 
            # PHP will make it available in $_SERVER['HTTP_X_JA3_HASH']. 
            fastcgi_param HTTP_X_JA3_HASH $ja3_hash; 
        }
    }
}
```

After reloading the Nginx configuration, the `X-JA3-Hash` header will be automatically available to your PHP application.

---

### Configuration with Apache

For Apache, obtaining the JA3 fingerprint is less straightforward because there is no standard module as widely available as the one for Nginx.

#### Option 1: `mod_ssl_ja3` module (Recommended)

The best approach is to use a third-party module like `mod_ssl_ja3`. You will need to compile and load it into your Apache configuration. Once the module is installed and enabled, you can add the JA3 header to your requests using the `RequestHeader` directive in your Virtual Host configuration:

```apache
<VirtualHost *:443>
    ServerName yourdomain.com
    # ... SSL configuration ...

    # The JA3_HASH environment variable is provided by mod_ssl_ja3
    RequestHeader set X-JA3-Hash "%{JA3_HASH}e"

    # ... your PHP application configuration ...
</VirtualHost>
```

#### Option 2: Using a Reverse Proxy in front of Apache

If you cannot compile modules for Apache, a very robust alternative is to place another service in front to handle TLS termination. **HAProxy** is an excellent choice for this, as it can calculate the JA3 hash natively and add it as a header before forwarding the request (via plain HTTP) to Apache.

This architecture is common in high-performance environments and offers great flexibility.

---

<a id="nodejs-quickstart"></a>
## NodeJS Quickstart

### Prerequisites for Node.js

Ensure you have middleware for parsing cookies (like `cookie-parser`) and request bodies (like `express.json` and `express.urlencoded`) set up in your Express application *before* the `powMiddleware`.

### Configuration
Define a secret key for signing PoW tickets in your environment variables.

```bash
export POW_SECRET="your_secret_key_of_at_least_32_characters"
```

### Integration Example

To simplify setup, `fingerprint` provides pre-configured security profiles for common use cases. You can use the `createSecurityProfile` helper to load a profile and optionally extend it with your own settings.

Available profiles:
-   `balanced` (default): A general-purpose configuration suitable for most websites.
-   `strict`: A more aggressive configuration for sensitive applications.
-   `api`: Optimized for protecting API endpoints, with a higher sensitivity to request patterns.
-   `blog`: Tuned to detect content scraping and comment spam.
-   `ecommerce`: A strict profile focused on preventing inventory scalping, price scraping, and account takeover.

```javascript
import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';
import { powMiddleware, createSecurityProfile } from '@anonympins/fingerprint'; // Adjust the path

const app = express();
app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Array to store traffic analysis data for the auto-tuner.
const trafficData = [];

// 1. Choose a base profile (e.g., 'balanced', 'strict', 'api').
// 2. (Optional) Define your custom overrides. These will be deeply merged with the base profile.
const securityConfig = createSecurityProfile('api', {
    // Example of overriding a specific threshold from the 'balanced' profile.
    thresholds: {
        low: 25, // Make the initial challenge slightly harder.
    },
    // Example of adding a custom whitelisting rule.
    whitelist: [
        { type: 'path_allowlist', entries: ['/api/v1/public-stats'] }
    ],
    // The logger is required if you enable auto-tuning.
    logger: (log) => trafficData.push(log),
    autotuning: {
        trafficData: trafficData,
        interval: 1800000, // 30 minutes
        minDataPoints: 200,
        savePath: './security-config.optimized.json' // (Optional) Save the best config found.
    },
});

// Create an instance of the middleware with your security configuration.
const powMiddlewareInstance = powMiddleware(securityConfig);

// Enable trust proxy if your app is behind a reverse proxy (Nginx, etc.)
// to correctly retrieve the client's IP.
app.set('trust proxy', 1);

// Apply the protection middleware to all routes or to specific ones.
app.use(powMiddlewareInstance);

app.get('/', (req, res) => {
    res.send('Welcome to the protected page!');
});

// Example of accessing the suspicion score in a subsequent middleware or route.
// The `fingerprint` object is attached to the request object by the middleware.
app.use((req, res, next) => {
    console.log(`Request from ${req.ip} has a suspicion score of: ${req.fingerprint?.score}`);
    next();
});

app.listen(3000, () => console.log('Server started on port 3000'));
```

### Full Configuration Example

If you prefer to define the entire configuration manually instead of using a profile, you can create a `securityConfig` object with all the parameters. All parameters are optional, but it is highly recommended to review and adjust them for your specific needs. The engine will warn you about any unknown keys in this configuration, helping you catch typos.

```javascript
import { powMiddleware, default_whitelist, default_analyzers } from '@anonympins/fingerprint';

const app = express();
app.use(cookieParser());
app.use(bodyParser.json()); // For parsing application/json
app.use(bodyParser.urlencoded({ extended: true })); // For parsing application/x-www-form-urlencoded

// Array to store traffic analysis data for the auto-tuner.
// In a real application, this could be a more robust logging system (e.g., writing to a file or a database).
const trafficData = [];
 
// Configuration of weights and thresholds for calculating the suspicion score.
// These values should be adjusted based on traffic and expected user behavior.
const securityConfig = {
    weights: {
        historyScore: 0.3,       // Penalizes IP rotation (proxy)
        rotationScore: 0.5,      // Penalizes rapid fingerprint changes (user-agent, etc.)
        headerAnomalyScore: 0.1, // Penalizes abnormal headers (missing UA, etc.)
        requestPatternScore: 0.6,// Penalizes bot-like request sequences (scraping, etc.)
        inconsistencyScore: 0.8, // Strongly penalizes inconsistency between the current and initial fingerprint (stolen cookie)
        behaviorScore: 0.7,      // Penalizes non-human interactions (no mouse/keyboard activity)
        honeypotScore: 1.0,      // Strongly penalizes bots filling hidden form fields
        crossLayerInconsistencyScore: 0.4, // Penalizes mismatches between client-side data (e.g., OS) and server-side headers (e.g., User-Agent)
        timeInconsistencyScore: 0.9, // Strongly penalizes large time gaps between client metric collection and server reception (replay attack)
        tlsSpoofingScore: 0.8      // Penalizes mismatches between the TLS fingerprint (JA3/JA4) and the User-Agent (client spoofing)
    },
    thresholds: {
        low: 20,    // Score from which a CPU challenge is issued
        medium: 45, // Score for a more difficult combined CPU/Memory challenge
        high: 75,   // Score for a very difficult challenge
        block: 95,  // Score above which the request is blocked outright (HTTP 404)
    },
    cpu: {
        minDifficultyBits: 8,
        maxDifficultyBits: 32,
    },
    // (Optional) Configure the duration (in milliseconds) for various temporary data.
    ticketMaxAge: 3600000, // 1 hour. Duration for which a solved challenge ticket is valid.
    challengeTtl: 300000, // 5 minutes. Time during which a challenge nonce is valid.
    deviceIdCookieMaxAge: undefined, // By default, it's a session cookie. Set a value in ms for a persistent cookie.
    challengePagePath: './path/to/your/custom-challenge-page.html', // (Optional) Path to a custom HTML template for the challenge page.
    verbose: process.env.NODE_ENV !== 'production', // Log detailed info in development, but not in production.
    patterns: { // (Optional) Initial values for request pattern detection, optimized by auto-tuner if enabled.
        velocityThreshold: 800,   // ms between requests to be considered "fast"
        burstThreshold: 1500,     // ms for identical requests to be a "burst"
        scrapeThreshold: 1000,    // ms for sequential requests to be "scraping"
        historySize: 10,          // Number of requests to keep for pattern analysis
        minSamples: 5,            // Minimum number of timings to collect before statistical analysis.
        regularityThreshold: 50,  // Standard deviation (ms) below which behavior is "too regular".
        benfordThreshold: 0.15,   // Benford's Law deviation threshold above which the distribution is "unnatural".
        patternWeight: 80,        // Strong, one-time penalty when a pattern is detected.
        decayFactor: 0.9,         // Factor by which the pattern score decreases over time.
        inactivityReset: 5000,    // Time (ms) after which the pattern score is reset.
    },
    honeypot: {
        // List of field names that are traps for bots.
        // These should be hidden in forms for humans, or be URL parameters your app never uses.
        fields: ['email_confirm', 'user_nickname', 'debug', 'test_mode', 'admin'], // (Optional)
        // List of URL paths that should never be accessed by a legitimate user.
        // A request to one of these paths will immediately flag the device as malicious.
        trapUrls: ['/wp-admin', '/.env', '/admin.php', '/phpmyadmin'], // (Optional)
        // Automatically detect common injection patterns. Can be a boolean or an array of specific types.
        // - `true`: Enables all available detections (default).
        // - `false`: Disables injection detection.
        // - `['sql', 'rce']`: Enables only SQL injection and Remote Command Execution detection.
        detectInjections: ['sql', 'rce', 'traversal', 'xxe', 'ssti', 'log4shell'], // (Optional, default: true)
        // (Optional) Plug in external analyzers. This allows you to extend detection with specialized libraries or custom logic.
        // Each function receives an object with all query and body data and should return `true` if a threat is detected.
        analyzers: [
            ...default_analyzers(), // Includes the default XSS analyzer.

            // Example 2: Enable a powerful WAF with ModSecurity and the OWASP Core Rule Set.
            // Requires `npm install modsecurity-nodejs` and downloading the OWASP CRS rules.
            // modsecurity_analyzer('/path/to/owasp-crs/crs-setup.conf'),

            // Example 3: A custom function to detect specific keywords (e.g., for anti-spam).
            (data) => {
                const spamKeywords = ['viagra', 'free money', 'crypto pump'];
                const dataString = JSON.stringify(data).toLowerCase();
                return spamKeywords.some(keyword => dataString.includes(keyword));
            }
        ]
    },
    // (Optional) Whitelisting configuration.
    whitelist: [
        // Option 1: Static IP Allowlist.
        // A simple array of IPs or CIDR ranges that are always allowed, bypassing all checks.
        // Useful for internal tools, trusted partners, or monitoring services.
        // This check is performed first for maximum efficiency.
        { type: 'allowlist', entries: [
                '192.168.1.100',      // A specific internal IP
                '203.0.113.0/24',     // A partner's network range
                '2001:db8::/32',      // An IPv6 range
                '2a01:e0a:129:57c0::1' // A specific IPv6 address
            ]},
        { type: 'hostname_allowlist', entries: [
                'google.com',      // A specific hostname
            ]},
        // Option 3: Host + Path Allowlist.
        // Bypasses checks for specific URL paths on specific hostnames. This is ideal for whitelisting
        // an API endpoint on one domain but not another. The entry is a combination of the host
        // header and the path. Supports wildcards (*) at the end of the path.
        { type: 'host_path_allowlist', entries: [
                'web.primals.net/api/*', // All paths starting with /api2 on web.primal.net
            ]},
        // Option 3: Path Allowlist.
        // Bypasses checks for specific URL paths. This is useful for trusted API endpoints, webhooks, or static content paths
        // that don't need protection. Supports wildcards (*) at the end of an entry.
        { type: 'path_allowlist', entries: [
                '/api/v1/webhooks/trusted-source', // Exact path
                '/api/v2/public/*',                // All paths starting with /api/v2/public/
            ]},

        // Allows a specific GraphQL query and all mutations•  
        {type: 'graphql_operation_allowlist',entries: [
            'query:GetPublicPosts',
                'mutation:*']},
        // Option 2: DNS-verified bots (e.g., search engine crawlers).
        // This uses a secure DNS lookup (reverse then forward) to verify the bot's identity.
        // The result is cached per IP to avoid repeated DNS lookups.
        // You can use the provided default list, which contains over 50 common bots, and extend it.
        ...default_whitelist(), // Use the defaults
        { userAgent: 'MyIndustrySpecificBot', hostnameSuffix: '.my-bot-verifier.com' }, // Add a custom bot
    ],
    // Optional: Custom function to identify static resources
    isStaticResource: (req) => req.path.startsWith('/static/'),
    // Optional: Custom function to identify API requests
    isApiRequest: (req) => req.path.startsWith('/api/') || req.headers.accept?.includes('application/json'),
    // The logger is required for auto-tuning. It collects data on requests.
    logger: (log) => trafficData.push(log),
    // (Optional) Configuration for the automatic threshold and pattern tuning.
    autotuning: {
        trafficData: trafficData,       // The data source for the genetic algorithm.
        interval: 1800000,              // Optimization cycle every 30 minutes (in ms).
        minDataPoints: 200,              // Minimum requests before starting an optimization cycle.
        maxDataPoints: 20000,             // Maximum log entries to keep in memory.
        savePath: './security-config.optimized.json' // (Optional) Save the best config found.
    },
    // Enables problem solving for suspicious activity (configurable in problems.config.json)
    enableUsefulWork: true,
    // (Optional) Path to the useful work configuration.
    usefulWorkConfigPath: './path/to/your/problems.config.json',
    // or usefulWorkConfig: [ /* ... your problem definitions ... */ ],
    // (Optional) Enable "dry run" mode. The engine will calculate scores and log intended actions
    // but will never actually block or challenge a request. Useful for testing new configs in production.
    dryRun: false,
};


// Create an instance of the middleware with your security configuration.
const powMiddlewareInstance = powMiddleware(securityConfig);
```


---

## Advanced Behavioral Analysis

The `FingerprintEngine` includes sophisticated behavioral analysis to detect non-human patterns. This analysis is performed by the `getRequestPatternScore` function, which is a stateful check that looks for repetitive or unnaturally fast requests from a single device.

This function uses several configurable parameters to identify suspicious behavior:

### Statistical Analysis (Regularity and Benford's Law)

To counter more advanced bots that might try to randomize their request timings, the engine employs statistical analysis.

*   **Regularity Detection**: The system also calculates the standard deviation of the time intervals between requests. A very low standard deviation indicates an unnaturally regular, "cron-like" behavior, which is a strong signal of automation.
*   **Benford's Law Analysis**: Benford's Law states that in many naturally occurring sets of numbers, the leading digit is more likely to be small. The timings between a human's requests tend to follow this natural distribution, whereas a bot's randomized delays often do not. The engine penalizes distributions that violate this law.

### Core Pattern Detection Parameters

These parameters form the basis of the statistical request pattern analysis:

*   `regularityThreshold`: (Default: 50ms) The standard deviation in milliseconds below which the request timing is considered "too regular" and robotic.
*   `benfordThreshold`: (Default: 0.15) The deviation score from Benford's Law above which the timing distribution is considered "unnatural".
*   `patternWeight`: (Default: 80) A strong, one-time penalty applied to the suspicion score if either a regularity or Benford's Law anomaly is detected.

*   `benfordMinSamples`: (Default: 15) The minimum number of request timings to collect before performing a Benford's Law test.
*   `benfordWeight`: (Default: 50) The weight applied to the suspicion score if the distribution of timings significantly deviates from Benford's Law.

## Customizing the Challenge Page

You can provide your own HTML template for the Proof-of-Work challenge page to maintain a consistent user experience with your brand.

1.  **Configuration**: In your `securityConfig`, specify the path to your template file using the `challengePagePath` option.

    ```javascript
    const securityConfig = {
        // ... other options
        challengePagePath: './path/to/your/custom-challenge-page.html',
    };
    ```

2.  **Template Placeholders**: Your HTML file **must** contain the following placeholders. The system will replace them with the dynamic JavaScript code required to run the challenge.

    *   `<!-- FINGERPRINT_SOLVER_SCRIPT -->`: This will be replaced by the script that contains the logic for solving the CPU and memory challenges.
    *   `<!-- FINGERPRINT_CHALLENGE_SCRIPT -->`: This will be replaced by the script that initiates the challenge with the specific parameters for the current request (nonce, difficulty, etc.).
    *   `<!-- FINGERPRINT_TRAPS -->`: This will be replaced by hidden "honeypot" links designed to trap simple bots. This placeholder is crucial for an effective defense.

#### Example Custom HTML Template

Here is a basic example of what your `custom-challenge-page.html` could look like:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Verification</title>
    <style>
        body { font-family: sans-serif; text-align: center; padding-top: 50px; }
        h1 { color: #333; }
    </style>
</head>
<body>
    <h1>Please wait while we verify your connection...</h1>
    <div id="loader" style="margin:20px;">⚙️ Initializing verification...</div>

    <script><!-- FINGERPRINT_SOLVER_SCRIPT --></script>
    <script><!-- FINGERPRINT_CHALLENGE_SCRIPT --></script>
    <!-- FINGERPRINT_TRAPS -->
</body>
</html>
```
## Public API

In addition to the main middleware, several functions are exported to allow for more advanced integrations.

### Main Functions

#### `powMiddleware(securityConfig)`
The main Express middleware. It orchestrates identification, suspicion calculation, and challenge issuance. It is the main entry point of the library.

#### `configureStore(store)`
Allows replacing the in-memory store with an external datastore (like Redis) for persistence and scaling.
The library provides ready-to-use adapters for popular datastores like **Redis**, **MongoDB**, and any **SQL database** supported by Knex.js. These adapters automatically handle the Time-To-Live (TTL) required for temporary data like challenge secrets.

**Redis Example:**

```javascript
import { configureStore } from '@anonympins/fingerprint';
import { createRedisStore } from './redis-store.js';
import Redis from 'ioredis';

const redisClient = new Redis(process.env.REDIS_URL);
const redisStore = createRedisStore(redisClient);
configureStore(redisStore);
```

**MongoDB Example:**

```javascript
import { configureStore } from './fingerprint.js';
import { createMongoDbStore } from './mongodb-store.js';
import { MongoClient } from 'mongodb';

const mongoClient = new MongoClient(process.env.MONGODB_URL);

// It's recommended to connect before your application starts listening.
await mongoClient.connect(); 

const mongoStore = createMongoDbStore(mongoClient.db('your-db-name'), 'sessions'); // 'sessions' is the collection name
configureStore(mongoStore);

// IMPORTANT: For automatic expiration of challenges and other temporary data to work,
// you must create a TTL index on the `expiresAt` field in your MongoDB collection.
// Run this command in the mongo shell:
// db.sessions.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 })
```

**SQL Example (with Knex.js):**

```javascript
import { configureStore } from './fingerprint.js';
import { createSqlStore } from './sql-store.js';
import knex from 'knex';

const knexClient = knex({
  client: 'pg', // or 'mysql', 'sqlite3', etc.
  connection: process.env.DATABASE_URL,
});

const sqlStore = createSqlStore(knexClient, 'fingerprint_sessions'); // 'fingerprint_sessions' is the table name
configureStore(sqlStore);

// IMPORTANT: For automatic expiration of challenges and other temporary data to work,
// your table must have an `expiresAt` column. The store will handle cleanup of expired rows,
// but you must create the table yourself.
// Example schema for PostgreSQL:
// CREATE TABLE fingerprint_sessions (
//   "key" VARCHAR(255) PRIMARY KEY,
//   "value" TEXT NOT NULL,
//   "expiresAt" TIMESTAMPTZ
// );
```

#### `identifyRequest(req, res)`
An asynchronous function that returns an identification string for a given request, based on its suspicion level (`device:<id>`, `suspicious_medium:<ip>`, etc.). Useful for integration with a custom rate-limiter.

```javascript
import { RateLimiterMemory } from 'rate-limiter-flexible';
import { identifyRequest } from './fingerprint.js';

const rateLimiter = new RateLimiterMemory({
    keyPrefix: 'rate_limit',
    points: 10,
    duration: 1,
});

app.use(async (req, res, next) => {
    try {
        const key = await identifyRequest(req, res);
        await rateLimiter.consume(key);
        next();
    } catch (err) {
        res.status(429).send('Too Many Requests');
    }
});
```

### Utilities

#### `isTicketValid(ip, ticket)`
Checks the validity of a `pow_clearance` cookie. Returns `true` if the ticket is present, not expired, and correctly signed for the given IP.

#### `FingerprintBuilder`
A class for building granular server-side fingerprints.

```javascript
const builder = new FingerprintBuilder();
builder.add("ua", req.headers["user-agent"]);
builder.add("os", req.headers["sec-ch-ua-platform"]);
const fp = builder.toString(); // "os:hash1|ua:hash2"
```

#### `getDeviceFingerprint()`
*Client-side function only.* Generates a detailed browser fingerprint using APIs like Canvas, WebGL, etc.
This is the primary function for client-side identification.

#### `generateRequestSignature(payload)`
*Client-side function only.* Creates a signature for an outgoing request. It combines the device fingerprint with a hash of the request's `payload`. This can be used on the server-side to verify that a request comes from a recognized device and that its payload has not been trivially altered.

```javascript
// On the client
const signature = generateRequestSignature({ action: 'update', id: 123 });
// Send signature in headers...
```

#### `generateClientSideSignature(payload, secret)`
*Client-side function only.* Generates a secure HMAC-SHA256 signature for a given `payload` using a `secret`.
**Security Note:** This function is powerful but should be used with caution. The `secret` must be managed securely. It is typically used with a temporary, single-use secret provided by the server for a specific action, rather than a long-lived shared secret embedded in the client-side code.

---

## Why Use the Client-Side Library? The Client + Server Synergy

At first glance, client-side checks might seem redundant with server-side honeypots and analysis. In reality, they form two complementary and synergistic lines of defense.

Imagine your server is a fortified castle:

-   **Server-Side Defense (the guards on the walls):** They inspect anyone who knocks on the gate. They are effective, but this means the enemy is already at your door, and your resources (guards) are mobilized for every interaction, legitimate or not.
-   **Client-Side Defense (scouts and traps in the forest):** They detect suspicious movements and neutralize threats *before* they even reach the castle walls. This saves the castle's resources for genuine visitors.

The client-side library (`fingerprint.client.js`) gives your server "eyes and ears" where it was previously blind, offering three major advantages:

1.  **Early Detection & Resource Savings:** A bot filling a client-side honeypot is flagged in its own browser. The server can then immediately block it based on the `X-Behavior-Metrics` header, saving CPU, memory, and bandwidth that would have been wasted processing a malicious request.
2.  **Richer Behavioral Data:** The server cannot see how a user interacts with a page. The client-side library can detect non-human behavior (no mouse movement, instant form fills) that is impossible to spot from the server alone.
3.  **More Robust Fingerprinting:** Server-side signals (IP, User-Agent) are easy to spoof. Client-side fingerprinting adds much stronger, hardware-based signals (Canvas, WebGL, CPU cores) that are significantly harder for bots to fake consistently.

### Strengths at a Glance

| Feature                 | Server-Side Only Approach                               | Client + Server Approach (with the library)                                |
| :---------------------- | :------------------------------------------------------ | :------------------------------------------------------------------------- |
| **Detection Point**     | **Reactive** (after the request is received)            | **Proactive** (before or during the request)                               |
| **Resource Usage**      | Server is engaged for every request, good or bad.       | Client-side pre-filtering saves significant server resources.              |
| **Behavioral Analysis** | Limited to request velocity and sequence.               | Rich data: mouse movement, typing rhythm, interaction with hidden elements. |
| **Fingerprint Evasion** | **Easy** for bots to spoof headers and rotate IPs.      | **Hard** for bots to fake hardware-level fingerprints (Canvas/WebGL).      |
| **Overall Strategy**    | Guards at the gate.                                     | Scouts in the field + Guards at the gate.                                  |

In short, the client-side library is not an alternative, but a **force multiplier** for the server-side defenses.

### Client-Side Integration: The `initializeClient` function

To simplify setup, all client-side features can be enabled and configured through a single, unified function: `initializeClient(config)`. This is the recommended approach.

```javascript
import { initializeClient } from '@anonympins/fingerprint/client';
 
/**
 * Initializes all client-side protections.
 * This is the recommended way to set up the client-side library.
 */
initializeClient({
  // (Optional, default: true) Enable mouse movement tracking to detect non-human patterns.
  // Set to `false` to disable.
  mouse: true,
 
  // (Optional, default: true) Enable keystroke dynamics tracking (timing between key presses).
  // Set to `false` to disable.
  keystrokes: true,
 
  // (Optional) An array of `name` attributes for hidden form fields that act as bot traps.
  honeypots: ['email_confirm', 'user_nickname', 'website_url'],

  // (Optional) An array of signed trap URLs provided by the server. The client will
  // dynamically inject these into the DOM to trap bots that parse the live DOM.
  trapUrls: ['/backups/db.sql.gz?sig=...', '/.env?sig=...'],
 
  // (Optional) Path to the WebAssembly loader script (`fp.js`) for accelerated hashing.
  // If provided, the client will attempt to load the WASM module. If it fails or is not available,
  // it will gracefully fall back to the pure JavaScript implementation.
  wasmPath: '/fp.js',
 
  // (Optional) Enables automatic protection for `fetch` requests.
  // If the `fetch` object is present, the protection is active.
  fetch: {
    // (Optional) An array of domains to protect. If empty or not provided, it protects same-origin requests by default.
    targetDomains: ['api.yourdomain.com', 'auth.yourdomain.com'],
    
    // (Optional, default: true) If enabled, the client will automatically intercept 429 challenge responses,
    // solve the PoW in the background, and retry the original request with the solution.
    // This makes the protection seamless for API clients that use this library.
    handleChallenges: true
  }
});
```

### Client-Side Behavioral Analysis

The following functions, available in `fingerprint.client.js`, allow for proactive, client-side detection of bot-like behavior. They collect metrics on user interaction which can be sent to the server for more accurate suspicion scoring. The server-side logic to interpret these metrics (via the `X-Behavior-Metrics` header) would need to be implemented as part of a custom scoring extension.

#### `startKeystrokeDynamicsTracker()`
*Client-side function only.* Starts tracking the timing between keystrokes. The average latency between key presses is a strong behavioral indicator. Humans have a natural, somewhat variable typing rhythm, whereas bots often simulate keystrokes with a fixed, unnaturally consistent delay, or paste text instantly (zero latency).

#### `startMouseEntropyTracker()`
*Client-side function only.* Starts tracking mouse movements on the page. It calculates a simple entropy score based on movement patterns. Human mouse movements are typically chaotic, whereas bots often have linear or no movement at all. This should be called once when your application's main component mounts.

#### `initializeHoneypots(fieldNames)`
*Client-side function only.* Sets up "traps" on hidden form fields. If a script automatically fills one of these fields, it's immediately flagged as a bot on the client side.

This provides a proactive, first-line defense against simple bots. By setting up traps directly in the browser, you can detect a bot the moment it interacts with a hidden field, rather than waiting for it to submit a form and consume server resources. This detection is then reported to the server via the `X-Behavior-Metrics` header, allowing for an immediate and efficient block.

- `fieldNames`: An array of strings corresponding to the `name` attributes of the honeypot input fields in your HTML.

### Advanced: Manual Wrapping with `protectedFetch`

If you prefer not to modify global functions or need fine-grained control over which requests are protected, you can use the `protectedFetch` wrapper. You must use this function instead of the standard `fetch` for your API calls.

- **`protectedFetch(resource, options)`**: A wrapper around the native `fetch` API that automatically enriches requests with security headers. It adds:
    - `X-Device-Fingerprint`: The client's device fingerprint.
    - `X-Behavior-Metrics`: A JSON string containing the metrics collected by the behavioral trackers (e.g., mouse entropy, honeypot interaction).

**Example:**

```javascript
import {
    initializeClient,
    protectedFetch
} from '@anonympins/fingerprint/client';

// Start tracking user behavior as soon as the app loads.
// Note: You still need to initialize the trackers even if you use protectedFetch manually.
initializeClient({ fetch: false }); // Disables automatic fetch patching

// Now, use protectedFetch for your specific API calls.
async function submitForm(data) {
    const response = await protectedFetch('/api/submit-data', {
        method: 'POST',
        body: JSON.stringify(data),
        headers: {'Content-Type': 'application/json'}
    });
}
```

## Advanced Features

### Architecture: `FingerprintEngine`

The core logic of the library is encapsulated within the `FingerprintEngine` class. The `powMiddleware` is essentially a lightweight wrapper that adapts this engine for use with Express.js.

The engine is responsible for:
1.  Receiving a `requestContext` (IP, headers, cookies, etc.).
2.  Calculating the suspicion score using the configured weights.
3.  Making a decision: `next`, `challenge`, or `redirect` (after solving a challenge).

Although not exported for direct public use, understanding its role can be useful for advanced integrations or debugging.

### Manual Integration (outside Express.js)

While `powMiddleware` is convenient for Express, you can use the `FingerprintEngine` directly in any Node.js server environment (e.g., native `http`, Fastify, Koa). This gives you full control over the request/response cycle.

**For concrete examples with Koa and Fastify, see our [Framework Integration Guide](https://github.com/anonympins/fingerprint/blob/main/INTEGRATION.md).**

The engine is a named export from the main module.

### Useful Proof-of-Work (`ProblemManager`)

Instead of issuing a generic Proof-of-Work, the system can dispatch a "useful" computational problem to a suspicious client. This allows harnessing the client's CPU cycles to solve complex problems (like optimization tasks) over time. This feature is managed by the `ProblemManager` class, which is enabled via the `enableUsefulWork: true` flag in the security configuration. The state of these problems is persisted via the configured datastore, allowing a cluster of servers to collaborate on solving them.

The `ProblemManager` reads its configuration asynchronously from `problems.config.json`, which defines the problems to be solved, the type of work units, and the initial state of the solutions.

While you typically won't interact with it directly, its methods are exported and can be used for monitoring or manual administration. The main instance is exported as `problemManager`.

#### `problemManager.dispatchWork(suspicionFactor)`

Selects a problem and generates a work unit for a client. The difficulty of the task (e.g., number of iterations) is scaled based on the client's `suspicionFactor`.

*   **`suspicionFactor`** (`number`): A factor to adjust the difficulty of the work unit.
*   **Returns**: (`object|null`) An object containing the `problemId` and the `task` to be sent to the client, or `null` if no problems are available.

#### `problemManager.integrateSolution(problemId, solutionData)`

Integrates a solution returned by a client into the problem's state. If the new solution is better than the existing one, it is saved as the new best solution.

*   **`problemId`** (`string`): The ID of the problem being updated.
*   **`solutionData`** (`object`): The solution data returned by the client (e.g., `{ solution, energy }`).

#### `problemManager.getBestSolutions([problemId])`

Retrieves the best solution currently known for one or all problems. This is useful for creating an API endpoint to view the progress of the distributed computation.

*   **`problemId`** (`string`, optional): The ID of a specific problem.
*   **Returns**: (`object|Array<object>|null`)
    *   If a `problemId` is provided, it returns an object with the best solution for that problem (`{ id, solution, score, lastUpdate }`).
    *   If no `problemId` is provided, it returns an array of these objects for all problems.

**Example: Creating an API endpoint to view solutions**

```javascript
import { problemManager } from '@anonympins/fingerprint'; // Adjust path

app.get('/api/problems/solutions', (req, res) => {
    const solutions = problemManager.getBestSolutions();
    res.json(solutions);
});

```

#### `getBestTuningSolution()`

Returns the last best solution object found by the auto-tuner. This is particularly useful for "FinOps" or for auditing the tuner's performance, as it allows you to log the exact configuration that the genetic algorithm identified as optimal.

*   **Returns**: (`object|null`) The best solution object `{ solution, objectives }` or `null` if no tuning cycle has completed yet. The `solution` property contains the optimized `weights`, `thresholds`, and `patterns`, while `objectives` contains the performance scores (e.g., false positive/negative rates) for that solution.

#### `problemManager.updateProblemPayload(problemId, newPayload)`

Updates the payload (parameters) of a specific problem by its ID. This allows for dynamic adjustment of problem configurations without restarting the server. When the payload is updated, the problem's current best solution and energy are reset, forcing the system to find a new optimal solution for the modified problem.

*   **`problemId`** (`string`): The ID of the problem to update.
*   **`newPayload`** (`object`): The new payload object that will replace the existing one.
*   **Returns**: (`boolean`) `true` if the update was successful, `false` otherwise.

**Example: Changing the number of facilities for `facility_location_challenge`**

---

## NodeJS raw integration
**Workflow:**

1.  **Instantiate the Engine**: Create an instance with your `securityConfig`.
2.  **Build the `requestContext`**: On each request, manually create a context object. It must include `clientIp`, `path`, `cookies`, `query`, `headers`, and mock `rawReq`/`rawRes` objects for cookie handling.
3.  **Process the Request**: Call `engine.processRequest(requestContext)`. This method is asynchronous.
4.  **Handle the Decision**: The engine returns a decision object (`{ action: 'challenge' | 'redirect' | 'next', ... }`). You are responsible for implementing the corresponding HTTP response.

**Example with native Node.js `http` server:**

```javascript
import http from 'http';
import { FingerprintEngine } from '@anonympins/fingerprint'; // Adjust path

const securityConfig = { /* ... your config ... */ };
const engine = new FingerprintEngine(securityConfig);

const server = http.createServer(async (req, res) => {
    // 1. Manually build the context
    const requestContext = {
        clientIp: req.socket.remoteAddress,
        path: req.url.split('?')[0],
        cookies: {}, // Parse cookies from req.headers.cookie
        query: Object.fromEntries(new URL(req.url, `http://${req.headers.host}`).searchParams),
        headers: req.headers,
        rawReq: req, // Pass the raw request
        rawRes: res, // Pass the raw response for cookie setting
    };

    // 2. Process and get a decision
    const decision = await engine.processRequest(requestContext);

    // The decision object now contains the score and the raw suspicion vector.
    // You can use it for logging or custom logic.
    console.log(`Request from ${requestContext.clientIp} processed with score: ${decision.score}`);

    // 3. Act on the decision
    if (decision.action === 'challenge') {
        res.writeHead(decision.status, { 'Content-Type': 'text/html' });
        res.end(decision.body);
    } else if (decision.action === 'redirect') {
        // The engine sets the cookie directly on `res` via `rawRes`
        res.writeHead(302, { 'Location': decision.path });
        res.end();
    } else { // 'next'
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Welcome to the protected page!');
    }
});

server.listen(3000, () => console.log('Server with manual fingerprint engine started on port 3000'));
```

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.