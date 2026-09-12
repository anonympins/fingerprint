# Configuration Options Reference

This document provides a comprehensive reference for all configuration options available in the `fingerprint` protection engine, with a specific focus on the **21 score weights** used to compute the final suspicion score.

---

## Complete Configuration Template (JSON)

Here is a complete representation of a custom security configuration containing all available suspicion weights, thresholds, and detection subsystem parameters:

```json
{
  "verbose": false,
  "dryRun": false,
  "challengeNewDevices": false,
  "allowCrossNetworkRoaming": true,
  "similarityThreshold": 0.70,
  "ticketMaxAge": 3600000,
  "challengeTtl": 300,
  "deviceIdCookieMaxAge": 2592000000,
  "thresholds": {
    "low": 20,
    "medium": 45,
    "high": 75,
    "block": 95
  },
  "weights": {
    "historyScore": 0.30,
    "rotationScore": 0.50,
    "headerAnomalyScore": 0.10,
    "requestPatternScore": 0.60,
    "inconsistencyScore": 0.80,
    "behaviorScore": 0.70,
    "honeypotScore": 1.00,
    "crossLayerInconsistencyScore": 0.40,
    "timeInconsistencyScore": 0.90,
    "tlsSpoofingScore": 0.80,
    "botScore": 1.00,
    "cookieDroppingScore": 0.90,
    "threatIntelScore": 0.40,
    "clientHintsInconsistencyScore": 0.70,
    "clickVarianceScore": 0.60,
    "subnetScore": 0.50,
    "botnetClusterScore": 0.60,
    "tcpAnomalyScore": 0.80,
    "quicAnomalyScore": 0.80,
    "renderingAnomalyScore": 0.80,
    "ipReputationScore": 0.50
  },
  "patterns": {
    "velocityThreshold": 800,
    "burstThreshold": 1500,
    "scrapeThreshold": 1000,
    "historySize": 10,
    "minSamples": 5,
    "regularityThreshold": 50,
    "benfordThreshold": 0.15,
    "patternWeight": 80,
    "decayFactor": 0.90,
    "inactivityReset": 5000,
    "regularityRatio": 0.40,
    "benfordRatio": 0.30,
    "enumerationRatio": 0.30
  },
  "honeypot": {
    "fields": ["email_confirm", "admin_login_bypass"],
    "trapUrls": ["/wp-admin", "/.env", "/.git/config"],
    "detectInjections": true
  },
  "threatIntel": {
    "knownIps": []
  },
  "cpu": {
    "minDifficultyBits": 8,
    "maxDifficultyBits": 16
  },
  "pospace": {
    "sizeMb": 100,
    "numQueries": 10
  }
}
```

---

## Detailed Score Weights Reference (The 21 Invariants)

The following table details the role of each weight in the `weights` object. These weights determine how heavily each suspicion indicator influences the final score (calculated dynamically out of 100).

| Weight Name | Default (`balanced`) | Impact & Role |
| :--- | :---: | :--- |
| **`botScore`** | `1.00` | **Extreme**. Triggers when client-side environment checks explicitly detect browser automation frameworks (e.g., Selenium, Puppeteer). |
| **`honeypotScore`** | `1.00` | **Extreme**. Triggers when a client visits hidden/forbidden trap URLs or enters data in hidden inputs (honeypots). |
| **`timeInconsistencyScore`** | `0.90` | **Very High**. Penalizes requests where client and server clocks drastically differ, detecting replayed behavioral telemetry. |
| **`cookieDroppingScore`** | `0.90` | **Very High**. Penalizes clients that make rapid sequential requests but systematically delete or drop their session cookies. |
| **`inconsistencyScore`** | `0.80` | **High**. Triggered when the current device hardware hash does not match the anchor hash originally bound to the cookie. |
| **`tlsSpoofingScore`** | `0.80` | **High**. Penalizes TLS signatures (JA3/JA4) that mismatch the claimed HTTP User-Agent. |
| **`tcpAnomalyScore`** | `0.80` | **High**. Detects OS-level spoofing by comparing TCP packet parameters (TTL, Window Size) with the claimed User-Agent OS. |
| **`quicAnomalyScore`** | `0.80` | **High**. Identifies spoofed flow parameters on HTTP/3 and QUIC transport streams. |
| **`renderingAnomalyScore`** | `0.80` | **High**. Exposes headless browsers and virtualized graphics layers (e.g., SwiftShader) using rendering jitter telemetry. |
| **`behaviorScore`** | `0.70` | **High**. Analyzes real-time mouse speed, acceleration, keystroke latency, and scroll patterns to flag bot-like interactions. |
| **`clientHintsInconsistencyScore`** | `0.70` | **High**. Detects inconsistencies between user-agent strings and modern client hints headers (`sec-ch-ua`). |
| **`requestPatternScore`** | `0.60` | **Medium**. Evaluates rate, statistical intervals (Benford's Law), and path traversal patterns for scrapers. |
| **`botnetClusterScore`** | `0.60` | **Medium**. Grouping indicator. Raises suspicion if multiple distinct IPs share a mathematically identical hardware fingerprint within a 10-minute window. |
| **`clickVarianceScore`** | `0.60` | **Medium**. Penalizes clients that click on the exact same pixel coordinates repeatedly, detecting UI automation. |
| **`subnetScore`** | `0.50` | **Medium**. Elevates risk if other IPs in the same subnet CIDR block (/24 for IPv4, /48 for IPv6) recently triggered anomalies. |
| **`ipReputationScore`** | `0.50` | **Medium**. Leverages short-term history of individual IP addresses that failed previous proof-of-work challenges. |
| **`crossLayerInconsistencyScore`** | `0.40` | **Low**. Checks minor cross-layer anomalies like viewport sizes exceeding physical screen size. |
| **`threatIntelScore`** | `0.40` | **Low**. Penalizes IPs that are registered as commercial VPNs, proxies, or Tor exit nodes. |
| **`rotationScore`** | `0.50` | **Medium**. Flags devices changing hardware-based fingerprints rapidly over a short time. |
| **`historyScore`** | `0.30` | **Low**. Monitors the total number of distinct IPs associated with a single device ID cookie. |
| **`headerAnomalyScore`** | `0.10` | **Low**. Simple parsing checks on headers (e.g., missing basic browser headers). |

---

## Core Engine Controls

### Global Controls
* **`verbose`** *(bool, default: `false`)*: Enables deep server-side log output.
* **`dryRun`** *(bool, default: `false`)*: Intended block and challenge actions are logged, but requests are always allowed to pass through (`next`). Useful for evaluating auto-tuner impact in production safely.
* **`challengeNewDevices`** *(bool, default: `false`)*: Forces a proof-of-work challenge on all new devices by setting their initial score to the `low` threshold.
* **`allowCrossNetworkRoaming`** *(bool, default: `true`)*: If `true`, a user can switch networks (e.g., from Home Wi-Fi to 4G) without being re-challenged, provided their hardware-based fingerprint remains absolutely identical.
* **`similarityThreshold`** *(float, default: `0.70`)*: The similarity coefficient (0 to 1) required to consider two composite fingerprints a match.

### Timings & Expirations
* **`ticketMaxAge`** *(int, default: `3600000`)*: Maximum lifespan of a clearance ticket (PoW resolution cookie) in milliseconds (default: 1 hour).
* **`challengeTtl`** *(int, default: `300`)*: Lifespan of a generated challenge session in seconds (default: 5 minutes).
* **`deviceIdCookieMaxAge`** *(int, default: `2592000000`)*: Lifespan of the `device_id` cookie in milliseconds (default: 30 days).

---

## Subsystems Configuration

### `patterns` (Request Sequences Analysis)
* **`velocityThreshold`**: High-frequency interval threshold (ms).
* **`burstThreshold`**: Fast retry trigger threshold (ms).
* **`scrapeThreshold`**: Absolute crawl limit interval (ms).
* **`historySize`**: The size of the request sliding window.
* **`minSamples`**: Minimum timing intervals required before executing Benford and regularity checks.
* **`decayFactor`**: Rate at which suspicion scores decay during inactivity.

### `honeypot` (Form and URL Traps)
* **`fields`**: List of hidden inputs to inject into HTML shadow forms.
* **`trapUrls`**: Hidden asset paths that normal users never crawl.
* **`detectInjections`** *(bool/array)*: Enables SQLi, XSS, RCE, and path traversal detection.

### `cpu` (Target CPU PoW)
* **`minDifficultyBits`**: Minimum zero-bit difficulty for low suspicion requests.
* **`maxDifficultyBits`**: Maximum zero-bit difficulty for highly suspicious requests.

### `pospace` (Proof of Space)
* **`sizeMb`**: Size of the indexed storage space to generate locally (MB).
* **`numQueries`**: Number of block read queries generated by the server.

---

## Profiles

For quick starts without manually defining everything, use pre-made profiles:

| Profile Name | Target / Use-case |
 | :--- | :--- |
| `balanced` | Standard websites, balanced UX & security. |
| `strict` | High security / sensitive dashboards. All new devices are challenged. |
| `api` | Focused heavily on rate limit patterns and API scrapers. |
| `blog` | Lenient on human readers, heavy on anti-scraping and spam comment honeypots. |
| `ecommerce` | Strict tracking against scalper bots and account takeover. |

### Profile Usage

**Node.js**:
 ```javascript
 import { createSecurityProfile } from '@anonympins/fingerprint';
 
 const config = createSecurityProfile('ecommerce', {
     verbose: true
     // overrides here...
 });

```

**PHP**
```php
<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

use Anonympins\Fingerprint\Config\SecurityProfiles;
use Anonympins\Fingerprint\DirectFingerprint;

// Création du profil avec surcharges
$securityConfig = SecurityProfiles::createSecurityProfile('ecommerce', [
    'verbose' => true, 
]);

// Initialisation du protecteur avec la configuration
$protector = new DirectFingerprint($securityConfig);

// Analyse et protection de la requête (bloque ou lance un challenge si suspect)
$fingerprint = $protector->protect();

// Si le script continue, la requête est légitime
echo "Welcome on the secured page !";
```

# Auto-Tuning & Traffic Data Pruning Options

The `autotuning` engine dynamically adjusts your thresholds and weights using a background genetic algorithm. It profiles real-world traffic to find the optimal trade-off between user experience (minimizing false-positive challenges for human users) and strict security (maximizing bot detection).

To prevent unbounded memory growth, the engine features an integrated **Traffic Data Pruning** mechanism to automatically prune old logs.

### Configuration Details

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `trafficData` | `Array` | `[]` | In-memory storage array that accumulates incoming request telemetry vectors for analysis. |
| `interval` | `number` | `1800000` | The frequency (in milliseconds) at which the genetic algorithm runs (e.g., 30 minutes). |
| `minDataPoints` | `number` | `200` | Minimum number of recorded requests needed before the tuning algorithm can execute. |
| `maxDataPoints` | `number` | `20000` | Hard cap on the number of traffic entries stored in memory to prevent heap exhaustion. |
| `maxAgeMs` | `number` | `86400000` | Time-to-Live (TTL) for traffic logs in milliseconds. Stale logs older than this limit (e.g., 24 hours) are permanently pruned. |
| `clearAfterTuning` | `boolean` | `true` | If set to `true`, flushes the accumulated traffic data after completing a successful optimization cycle. |
| `savePath` | `string` | `undefined` | The local filesystem path where the optimized config JSON will be persisted. |
| `onCleanup` | `Function` | `undefined` | Event callback executed whenever logs are pruned. Receives an array of the removed logs as its argument. |

### Example of Background Tuning Optimization Flow

1. **Accumulation**: The engine collects telemetry metadata across requests, populating `trafficData`.
2. **Pruning**: Periodic tasks run to compare data timestamps against `maxAgeMs` to remove expired data.
3. **Evaluation**: Once `interval` is reached and data size exceeds `minDataPoints`, the genetic tuner initiates.
4. **Optimization**: It executes a multi-objective optimization (Pareto front) to find the best configuration that would have separated the historical benign traffic from anomalous scores.
5. **Persistence & Hot-Reload**: The optimized config is saved to `savePath` and seamlessly applied in memory.