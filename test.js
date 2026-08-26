import http from 'http';
import { FingerprintEngine } from './fingerprint.js'; // Adjust path

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
const engine = new FingerprintEngine(securityConfig);

const server = http.createServer(async (req, res) => {
    // Helper function to parse cookies from the header string
    const parseCookies = (cookieHeader) => {
        if (!cookieHeader) return {};
        return cookieHeader.split(';').reduce((acc, cookie) => {
            const [key, value] = cookie.split('=').map(c => c.trim());
            if (key) acc[key] = value;
            return acc;
        }, {});
    };

    // 1. Manually build the context
    const requestContext = {
        clientIp: req.socket.remoteAddress,
        path: req.url.split('?')[0],
        cookies: parseCookies(req.headers.cookie), // FIX: Correctly parse cookies
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
        // The engine now returns the correct status (e.g., 404) for challenges.
        // We should respect this status code.
        res.writeHead(decision.status, { 'Content-Type': 'text/html' });
        res.end(decision.body);
    } else if (decision.action === 'redirect') {
        // The engine now returns the cookie to be set in the decision object.
        const headers = { 'Location': decision.path };
        if (decision.cookie) {
            const { name, value, options } = decision.cookie;
            let cookieString = `${name}=${value}`;
            for (const key in options) {
                cookieString += `; ${key}=${options[key]}`;
            }
            headers['Set-Cookie'] = cookieString;
        }
        res.writeHead(302, headers);
        res.end();
    } else { // 'next'
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        // FIX: Distinguish between the root path (which can trigger a challenge)
        // and a final destination page to avoid redirection loops.
        const destinationMessage = requestContext.path === '/' ?
            'Welcome! You are on the main page. Try accessing /protected to see the engine in action.' :
            'Welcome to the protected page!';
        res.end(destinationMessage);
    }
});

server.listen(3000, () => console.log('Server with manual fingerprint engine started on port 3000'));
