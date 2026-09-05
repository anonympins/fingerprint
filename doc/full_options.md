# Full Configuration Options

This document lists all configuration properties available for both PHP and Node.js.

## PHP Configuration Array Example

Here is a comprehensive overview of the full configuration array you can pass to the engine in PHP:

 ```php
 <?php
 
 $securityConfig = [
     // Suspicion metrics weights. Sum does not need to equal 1.0.
     'weights' => [
         'historyScore' => 0.3,       // Penalizes IP rotation (proxy)
         'rotationScore' => 0.5,      // Penalizes rapid fingerprint changes
         'headerAnomalyScore' => 0.1, // Penalizes missing or abnormal headers
         'requestPatternScore' => 0.6,// Penalizes automated scrape patterns
         'inconsistencyScore' => 0.8, // Penalizes cookie hijacking
         'behaviorScore' => 0.7,      // Penalizes non-human interactions (mouse/keys)
         'honeypotScore' => 1.0,      // Penalizes bots filling trap inputs
         'crossLayerInconsistencyScore' => 0.4, // Penalizes mismatched OS vs User-Agent
         'timeInconsistencyScore' => 0.9,       // Penalizes replayed metric timestamps
         'tlsSpoofingScore' => 0.8,             // Penalizes mismatched JA3/JA4 vs User-Agent
         'botScore' => 1.0,                     // Penalizes automated environments (WebDriver, etc.)
         'clientHintsInconsistencyScore' => 0.7, // Penalizes mismatched Client Hints vs User-Agent
     ],
     // Enforcement thresholds
     'thresholds' => [
         'low' => 20,    // Triggers minimal CPU challenge
         'medium' => 45, // Triggers combined CPU/Memory challenge
         'high' => 75,   // Triggers severe CPU/Memory challenge
         'block' => 95,  // Instantly blocks the client
     ],
     'cpu' => [
         'minDifficultyBits' => 8,
         'maxDifficultyBits' => 24,
     ],
     // Time limits (in milliseconds)
     'ticketMaxAge' => 3600000,      // 1 hour clearance ticket lifespan
     'challengeTtl' => 300000,       // 5 minutes nonce validity
     'deviceIdCookieMaxAge' => null, // Session cookie (or set integer in ms)
     'challengePagePath' => null,    // Custom challenge page template path
     'verbose' => false,             // Debug logging toggle
     
     // Settings for request sequence / scraper analysis
     'patterns' => [
         'historySize' => 10,
         'minSamples' => 5,
         'regularityThreshold' => 50,
         'benfordThreshold' => 0.15,
         'patternWeight' => 80,
         'decayFactor' => 0.9,
         'inactivityReset' => 5000,
     ],
     
     // Trap configuration
     'honeypot' => [
         'fields' => ['email_confirm', 'user_nickname'],
         'trapUrls' => ['/wp-admin', '/.env'],
         'detectInjections' => ['sql', 'rce', 'traversal', 'xxe'],
     ],
     
     // Whitelist definitions
     'whitelist' => [
         [
             'type' => 'allowlist',
             'entries' => ['192.168.1.100', '203.0.113.0/24']
         ],
         [
             'type' => 'path_allowlist',
             'entries' => ['/api/public/*']
         ]
     ]
 ];
 ```
 
---

## Node.js Configuration Object Example

Here is the same full configuration tailored for Node.js:

 ```javascript
 const securityConfig = {
     weights: {
         historyScore: 0.3,
         rotationScore: 0.5,
         headerAnomalyScore: 0.1,
         requestPatternScore: 0.6,
         inconsistencyScore: 0.8,
         behaviorScore: 0.7,
         honeypotScore: 1.0,
         crossLayerInconsistencyScore: 0.4,
         timeInconsistencyScore: 0.9,
         tlsSpoofingScore: 0.8,
         clientHintsInconsistencyScore: 0.7
     },
     thresholds: {
         low: 20,
         medium: 45,
         high: 75,
         block: 95,
     },
     cpu: {
         minDifficultyBits: 8,
         maxDifficultyBits: 32,
     },
     ticketMaxAge: 3600000,
     challengeTtl: 300000,
     deviceIdCookieMaxAge: undefined,
     challengePagePath: './path/to/custom-challenge-page.html',
     verbose: process.env.NODE_ENV !== 'production',
     patterns: {
         velocityThreshold: 800,
         burstThreshold: 1500,
         scrapeThreshold: 1000,
         historySize: 10,
         minSamples: 5,
         regularityThreshold: 50,
         benfordThreshold: 0.15,
         patternWeight: 80,
         decayFactor: 0.9,
         inactivityReset: 5000,
     },
     honeypot: {
         fields: ['email_confirm', 'admin'],
         trapUrls: ['/wp-admin', '/.env'],
         detectInjections: ['sql', 'rce', 'traversal', 'xxe'],
         analyzers: [
             // Custom async/sync custom functions
             (data) => {
                 const spamKeywords = ['viagra', 'free money'];
                 const dataString = JSON.stringify(data).toLowerCase();
                 return spamKeywords.some(kw => dataString.includes(keyword));
             }
         ]
     },
     whitelist: [
         { type: 'allowlist', entries: ['127.0.0.1', '10.0.0.0/8'] },
         { type: 'path_allowlist', entries: ['/assets/*', '/favicon.ico'] }
     ],
     isStaticResource: (req) => req.path.startsWith('/static/'),
     isApiRequest: (req) => req.path.startsWith('/api/') || req.headers.accept?.includes('application/json'),
     logger: (log) => console.log('Log recorded:', log.type),
     autotuning: {
         trafficData: [],
         interval: 1800000, // 30 mins
         minDataPoints: 200,
         maxDataPoints: 20000,
         savePath: './security-config.optimized.json'
     },
     enableUsefulWork: true,
     dryRun: false,
     trustedProxies: ['127.0.0.1', '192.168.1.0/24'],
     wasm: './public',
 };
 ```
 
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