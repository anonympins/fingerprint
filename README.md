# fingerprint
![](https://img.shields.io/github/v/release/anonympins/fingerprint)
![](https://img.shields.io/github/license/anonympins/fingerprint)

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
    *   **Level 1 (Low Suspicion)**: CPU-based PoW challenge (SHA-256).
    *   **Level 2 (Medium Suspicion)**: Memory-intensive PoW challenge.
    *   **Level 3 (High Suspicion)**: Complex challenge (e.g., TSP - Traveling Salesperson Problem) or a CAPTCHA.

Once the challenge is solved, a clearance "ticket" is issued via a cookie, exempting the user from new challenges for a set period.

## Features

-   **Multi-Factor Fingerprinting**: Combines client-side data (`hardwareConcurrency`, `deviceMemory`, `screen`, `canvas`, `webgl`) and server-side data (`User-Agent`, `Client-Hints`).
-   **Weighted Suspicion Engine**: Calculates a score based on behavioral and technical indicators.
-   **Variable-Difficulty Proof-of-Work Challenges**:
    -   `cpu_target`: An "analog" CPU challenge where difficulty is finely tuned to the suspicion score.
    -   `memory`: A challenge that allocates an amount of memory proportional to the suspicion level.
    -   `tsp`: An optimization challenge (Traveling Salesperson Problem) for the most suspicious cases.
-   **Secure Ticket System**: Uses HMAC-SHA256 signatures to validate clearances and prevent tampering.
-   **Pluggable Datastore**: Supports external datastores like Redis for state persistence and scalability across multiple server instances.
-   **Express.js Middleware**: Easy integration into an Express application with `powMiddleware`.
-   **Timing Attack Protection**: Uses `crypto.timingSafeEqual` for secure ticket validation.

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
    medium: 45, // Score for a Memory challenge
    high: 75    // Score for a complex challenge (TSP/Captcha)
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

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for more details.