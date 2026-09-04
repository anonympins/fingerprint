# Node.js Integration Guide

This guide details how to integrate and use the `fingerprint` library within a Node.js ecosystem, using Express middleware or other raw routing systems.

## Prerequisites

Make sure you have middleware to parse cookies (like `cookie-parser`) and request bodies (like `express.json` and `express.urlencoded`) registered *before* applying the protection middleware.
 
---

## Express.js Middleware Integration

Using `powMiddleware` is the easiest way to protect your Express application.

 ```javascript
 import express from 'express';
 import cookieParser from 'cookie-parser';
 import bodyParser from 'body-parser';
 import { powMiddleware, createSecurityProfile } from '@anonympins/fingerprint';
 
 const app = express();
 app.use(cookieParser());
 app.use(bodyParser.json());
 app.use(bodyParser.urlencoded({ extended: true }));
 
 // 1. Create a security configuration from a preset profile (e.g. balanced, strict, api)
 const securityConfig = createSecurityProfile('balanced', {
     verbose: process.env.NODE_ENV !== 'production',
 });
 
 // 2. Apply the protection middleware
 app.use(powMiddleware(securityConfig));
 
 // 3. Enable trust proxy if your app is behind a reverse proxy (Nginx, Cloudflare...)
 app.set('trust proxy', 1);
 
 app.get('/', (req, res) => {
     res.send('Welcome to the protected page!');
 });
 
 app.listen(3000, () => console.log('Server started on port 3000'));
 ```
 
---

## Raw Node.js HTTP Integration (No Express)

If you are using Koa, Fastify, or native `http` modules, you can instantiate the `FingerprintEngine` manually to process incoming requests and act on decisions.


+
+## Next Steps
+
+* See [Full Configuration Options](full_options.md) to discover all options you can tune.
+* See [Client Side Integration](client_side.md) to enable proactive browser challenges and behavioral trackers.
Diff
+185
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