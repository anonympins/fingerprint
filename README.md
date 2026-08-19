# fingerprint

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

### Exemple d'intégration

```javascript
import express from 'express';
import cookieParser from 'cookie-parser';
import { powMiddleware } from './fingerprint.js'; // Ajustez le chemin

const app = express();
app.use(cookieParser());

// Activez la confiance dans le proxy si votre app est derrière un reverse proxy (Nginx, etc.)
// afin de récupérer correctement l'IP du client.
app.set('trust proxy', 1);

// Appliquez le middleware de protection à toutes les routes
// ou à des routes spécifiques.
app.use(powMiddleware);

app.get('/', (req, res) => {
  res.send('Bienvenue sur la page protégée !');
});

app.listen(3000, () => console.log('Serveur démarré sur le port 3000'));
```

## Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.
