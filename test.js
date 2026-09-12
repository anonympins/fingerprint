import express from 'express';
import cookieParser from 'cookie-parser';
import { powMiddleware, handleMetricsRequest } from './src/js/fingerprint.js'; // Adjust path

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
        timeInconsistencyScore: 0.9 // Strongly penalizes large time gaps between client metric collection and server reception (replay attack)
    },
    thresholds: {
        low: 20,    // Score from which a CPU challenge is issued
        medium: 45, // Score for a more difficult combined CPU/Memory challenge
        high: 75,   // Score for a very difficult challenge
        block: 95,  // Score above which the request is blocked outright (HTTP 404)
    },
};

const metricsRateLimiter = (() => {
    const ipRequestHistory = new Map();
    return (req, res, next) => {
        const ip = req.ip || req.socket?.remoteAddress || 'unknown';
        const now = Date.now();
        const windowMs = 60000; // 1-minute window
        const maxRequests = 10;   // Allow maximum 10 requests per window

        const history = (ipRequestHistory.get(ip) || []).filter(ts => now - ts < windowMs);
        if (history.length >= maxRequests) {
            return res.status(429).send('Too Many Requests: Metrics rate limit exceeded.');
        }
        history.push(now);
        ipRequestHistory.set(ip, history);
        next();
    };
})();

const app = express();

// Middleware pour analyser les cookies requis par le moteur de fingerprinting
app.use(cookieParser());

// Middleware PoW qui gère l'évaluation de la réputation et l'interception automatique par challenge PoW
app.use(powMiddleware(securityConfig));

// Route d'accueil
app.get('/', (req, res) => {
    res.send('Welcome! You are on the main page. Try accessing /protected to see the engine in action.');
});

// Route protégée
app.get('/protected', (req, res) => {
    res.send('Welcome to the protected page!');
});
app.get('/metrics', metricsRateLimiter, async (req, res) => {
    await handleMetricsRequest(req, res, securityConfig);
});
app.listen(3000, () => console.log('Server with Express and powMiddleware started on port 3000'));
