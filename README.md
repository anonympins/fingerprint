# fingerprint
![](https://img.shields.io/github/actions/workflow/status/anonympins/fingerprint/ci.yml)
![](https://img.shields.io/github/v/release/anonympins/fingerprint)
![](https://img.shields.io/github/license/anonympins/fingerprint)
![](https://img.shields.io/github/downloads/anonympins/fingerprint/total)
![](https://img.shields.io/github/watchers/anonympins/fingerprint)

An HTTP(S) client mitigation and anti-bot protection library for Node.js/Express, based on digital fingerprinting and dynamic Proof-of-Work (PoW) challenges.

## How It Works

This system is designed to identify and slow down bots and automated scripts by evaluating the "suspicion" level of each incoming request. Instead of outright blocking, it imposes challenges with a difficulty proportional to the suspicion score, penalizing bots without significantly impacting legitimate users.

The process unfolds in three steps:

1.  **Identification & Fingerprinting**: A unique fingerprint is generated for each device based on browser characteristics (client-side) and request headers (server-side). A `device_id` cookie is used to track the device over time.
2.  **Suspicion Score Calculation**: Several indicators are analyzed to calculate a suspicion score:
    *   **Header Anomalies**: Missing `User-Agent`, `Accept-Language`, etc.
    *   **Device Behavior**: Rapid fingerprint changes (User-Agent rotation).
    *   **IP Behavior**: An excessive number of different devices seen from the same IP, or a single device using a large number of IPs (proxy rotation).
    *   **Inconsistency**: A low similarity score between the current fingerprint and the initial one associated with the `device_id` (cookie theft detection).
3.  **Dynamic Challenge**: If the suspicion score exceeds a certain threshold, a challenge is presented to the user. The difficulty and type of challenge depend on the score:
    *   **Low to Medium Suspicion**: A combined CPU and Memory Proof-of-Work (PoW) challenge is issued. The difficulty of both the CPU (hash calculation) and Memory (allocation and computation) components scales progressively with the suspicion score. For low scores, the memory challenge is negligible, making it primarily a CPU task.
    *   **High Suspicion**: For the most suspicious requests, a complex challenge like the Traveling Salesperson Problem (TSP) or a CAPTCHA can be triggered. (Note: In the current implementation, this level also defaults to a high-difficulty combined CPU/Memory challenge).

Once the challenge is solved, a clearance "ticket" is issued via a cookie, exempting the user from new challenges for a set period.

## Features

-   **Multi-Factor Fingerprinting**: Combines client-side data (`hardwareConcurrency`, `deviceMemory`, `screen`, `canvas`, `webgl`) and server-side data (`User-Agent`, `Client-Hints`).
-   **Secure Ticket System**: Uses HMAC-SHA256 signatures to validate clearances and prevent tampering.
-   **Pluggable Datastore**: Supports external datastores like Redis for state persistence and scalability across multiple server instances.
-   **Express.js Middleware**: Easy integration into an Express application with `powMiddleware`.
-   **Timing Attack Protection**: Uses `crypto.timingSafeEqual` for secure ticket validation.
-   **Automatic Threshold Tuning**: (Optional) Includes a genetic algorithm-based optimizer (`startThresholdAutoTuning`) that analyzes real traffic to dynamically adjust suspicion thresholds (`low`, `medium`, `high`), improving bot detection accuracy and reducing false positives over time.

## Installation and Usage

This module is designed for a Node.js environment.

### Prerequisites

Ensure you have a cookie-parser middleware (like `cookie-parser`) set up in your Express application.

### Configuration

Define a secret key for signing PoW tickets in your environment variables.

```bash
export POW_SECRET="your_secret_key_of_at_least_32_characters"
```

### Integration Example

For the `powMiddleware` to work, it needs a configuration defining the weights of suspicion indicators and the challenge trigger thresholds.

```javascript
import express from 'express';
import cookieParser from 'cookie-parser';
// The `configurePow` function is a conceptual example. In the actual implementation,
// you would pass the configuration to the middleware, for example, via a factory function.
import { powMiddleware /*, configurePow */ } from './fingerprint.js'; // Adjust the path

const app = express();
app.use(cookieParser());

// Configuration of weights and thresholds for calculating the suspicion score.
// These values should be adjusted based on traffic and expected user behavior.
const securityConfig = {
    weights: {
        historyScore: 0.3,       // Penalizes IP rotation (proxy)
        rotationScore: 0.5,      // Penalizes rapid fingerprint changes (user-agent, etc.)
        headerAnomalyScore: 0.1, // Penalizes abnormal headers (missing UA, etc.)
        inconsistencyScore: 0.8  // Strongly penalizes inconsistency between the current and initial fingerprint (stolen cookie)
    },
    thresholds: {
        low: 20,    // Score from which a CPU challenge is issued
        medium: 45, // Score for a more difficult combined CPU/Memory challenge
        high: 75,   // Score for a very difficult challenge
        block: 95   // Score above which the request is blocked outright (HTTP 403)
    }
};

// In a real-world scenario, you would configure the middleware.
// For example: const configuredPowMiddleware = createPowMiddleware(securityConfig);
const powMiddlewareInstance = powMiddleware(securityConfig);

// Enable trust proxy if your app is behind a reverse proxy (Nginx, etc.)
// to correctly retrieve the client's IP.
app.set('trust proxy', 1);

// Apply the protection middleware to all routes or to specific routes.
// You would use the configured middleware here.
app.use(powMiddlewareInstance);

app.get('/', (req, res) => {
    res.send('Welcome to the protected page!');
});

// Example of accessing the suspicion score in a subsequent middleware or route.
// The `fingerprint` object is attached to the request by `powMiddleware`.
app.use((req, res, next) => {
    console.log(`Request from ${req.ip} has a suspicion score of: ${req.fingerprint?.score}`);
    next();
});

app.listen(3000, () => console.log('Server started on port 3000'));
```

## Public API

In addition to the main middleware, several functions are exported to allow for more advanced integrations.

### Main Functions

#### `powMiddleware(req, res, next)`
The main Express middleware. It orchestrates identification, suspicion calculation, and challenge issuance. It is the main entry point of the library.

#### `configureStore(store)`
Allows replacing the in-memory store with an external datastore (like Redis) for persistence and scaling.

```javascript
import { configureStore } from './fingerprint.js';
import { createRedisStore } from './redis-store.js'; // Assuming you have a redis store implementation

const redisStore = createRedisStore(process.env.REDIS_URL);
configureStore(redisStore);
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

#### `FingerprintBuilder` (Class)
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

The engine is available via the internal exports: `import { __internal } from './fingerprint.js'`.

**Workflow:**

1.  **Instantiate the Engine**: Create an instance with your `securityConfig`.
2.  **Build the `requestContext`**: On each request, manually create a context object. It must include `clientIp`, `path`, `cookies`, `query`, `headers`, and mock `rawReq`/`rawRes` objects for cookie handling.
3.  **Process the Request**: Call `engine.processRequest(requestContext)`.
4.  **Handle the Decision**: The engine returns a decision object (`{ action: 'challenge' | 'redirect' | 'next', ... }`). You are responsible for implementing the corresponding HTTP response.

**Example with native Node.js `http` server:**

```javascript
import http from 'http';
import { __internal } from './fingerprint.js'; // Adjust path

const { FingerprintEngine } = __internal;
const securityConfig = { /* ... your config ... */ };
const engine = new FingerprintEngine(securityConfig);

const server = http.createServer(async (req, res) => {
    // 1. Manually build the context
    const requestContext = {
        clientIp: req.socket.remoteAddress,
        path: req.url.split('?')[0],
        cookies: {}, // Parse cookies from req.headers.cookie
        query: {},   // Parse query string from req.url
        headers: req.headers,
        isStatic: /\.(js|css|png)$/.test(req.url),
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

### Automatic Threshold Tuning

Manually setting the `low`, `medium`, and `high` thresholds can be challenging. This library provides a powerful tool to automate this process based on real traffic data. It uses a genetic algorithm to find the optimal thresholds that maximize bot detection while minimizing the impact on legitimate users.

#### How to use it:

1.  **Enable Logging**: The auto-tuner needs data. You must provide a `logger` function in your security configuration. This function will be called for significant events (`challenge_issued`, `challenge_solved`, etc.).

2.  **Start the Tuner**: Call `startThresholdAutoTuning` with your live security configuration and the array where logs are stored.

```javascript
import { powMiddleware, startThresholdAutoTuning } from './fingerprint.js';

// Array to store traffic analysis data. In a real application, this could be
// a more robust logging system.
const trafficData = [];

const securityConfig = {
    weights: { /* ... your weights ... */ },
    thresholds: {
        low: 20,    // Initial values, will be optimized
        medium: 45,
        high: 75
    },
    // The logger is required for auto-tuning
    logger: (log) => trafficData.push(log)
};

// Start the background optimization process.
// The `securityConfig.thresholds` object will be mutated with optimized values.
startThresholdAutoTuning({
    securityConfig: securityConfig, // The config object to be updated
    trafficData: trafficData,       // The data source for the algorithm
    interval: 1800000,              // Optimization cycle every 30 minutes
    minDataPoints: 200              // Minimum requests before starting optimization
});

const powMiddlewareInstance = powMiddleware(securityConfig);
app.use(powMiddlewareInstance);
```

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.