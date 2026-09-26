/**
 * Service Worker for transparent network interception and credential enrichment.
 * Leaves global window.fetch native and untouched to prevent tampering detection.
 */

let clientCredentials = {
    fp: '',
    behavior: 1,
    targetDomains: []
};

self.addEventListener('install', () => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(self.clients.claim());
});

self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'UPDATE_CREDENTIALS') {
        if (typeof event.data.fp !== 'undefined') {
            clientCredentials.fp = event.data.fp;
        }
        if (typeof event.data.behavior !== 'undefined') {
            clientCredentials.behavior = event.data.behavior;
        }
        if (Array.isArray(event.data.targetDomains)) {
            clientCredentials.targetDomains = event.data.targetDomains;
        }
    }
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);

    // Only process HTTP and HTTPS requests
    if (!url.protocol.startsWith('http')) return;

    // Scope filtering: same-origin or configured domains
    const targets = clientCredentials.targetDomains;
    const shouldProtect = (targets.length === 0 && url.origin === self.location.origin) ||
                          (targets.length > 0 && targets.includes(url.hostname));

    if (!shouldProtect) return;

    event.respondWith((async () => {
        const newHeaders = new Headers(event.request.headers);

        if (clientCredentials.fp) {
            newHeaders.set('X-Device-Fingerprint', clientCredentials.fp);
        }
        if (typeof clientCredentials.behavior !== 'undefined') {
            newHeaders.set('X-Behavior-Metrics', String(clientCredentials.behavior));
        }

        const requestInit = {
            method: event.request.method,
            headers: newHeaders,
            credentials: event.request.credentials,
            cache: event.request.cache,
            redirect: event.request.redirect,
            referrer: event.request.referrer,
            integrity: event.request.integrity
        };

        if (event.request.mode !== 'navigate') {
            requestInit.mode = event.request.mode;
        }

        if (event.request.method !== 'GET' && event.request.method !== 'HEAD') {
            try {
                const bodyBlob = await event.request.clone().blob();
                if (bodyBlob.size > 0) requestInit.body = bodyBlob;
            } catch (e) {}
        }

        const modifiedRequest = new Request(event.request.url, requestInit);
        return fetch(modifiedRequest);
    })());
});