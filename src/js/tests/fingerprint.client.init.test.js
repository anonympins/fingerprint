import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {JSDOM} from 'jsdom';
import ClientLibrary from '../fingerprint.client.js';

// --- Setup JSDOM Environment ---
// Vitest peut être configuré pour le faire automatiquement, mais le faire manuellement
// ici rend le test explicite et portable.
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    url: 'http://localhost',
});

// In recent Node.js versions, some global properties like 'navigator', 'performance',
// and 'screen' are read-only. To ensure our JSDOM environment works correctly across
// all versions, we use Object.defineProperty to make these properties writable.
Object.defineProperty(global, 'window', { value: dom.window, writable: true });
Object.defineProperty(global, 'document', { value: dom.window.document, writable: true });
Object.defineProperty(global, 'navigator', { value: dom.window.navigator, writable: true });
Object.defineProperty(global, 'screen', { value: dom.window.screen, writable: true });
Object.defineProperty(global, 'performance', { value: dom.window.performance, writable: true });
if (typeof globalThis.crypto !== 'undefined') {
    Object.defineProperty(dom.window, 'crypto', { value: globalThis.crypto, writable: true, configurable: true });
}
Object.defineProperty(global, 'CustomEvent', { value: dom.window.CustomEvent, writable: true, configurable: true });

global.fetch = vi.fn(); // Mock global fetch
window.fetch = (...args) => global.fetch(...args);
global.Headers = dom.window.Headers;
global.Request = dom.window.Request;
global.URL = dom.window.URL;
global.TextEncoder = dom.window.TextEncoder;


describe('ClientLibrary.initializeClient', () => {

    // On utilise des espions (spies) pour vérifier si les méthodes internes sont appelées.
    let startMouseSpy, startKeystrokeSpy, startClickSpy, startTouchSpy, startMotionSpy, startRenderingSpy, initWasmSpy, initHoneypotsSpy, injectTrapsSpy, initFetchSpy, injectPhantomTrapsSpy;

    beforeEach(() => {
        // Réinitialiser l'état du client avant chaque test
        ClientLibrary._resetCache();

        // Créer les espions sur les méthodes internes
        startMouseSpy = vi.spyOn(ClientLibrary, 'startMouseEntropyTracker');
        startKeystrokeSpy = vi.spyOn(ClientLibrary, 'startKeystrokeDynamicsTracker');
        startClickSpy = vi.spyOn(ClientLibrary, 'startClickTracker');
        startTouchSpy = vi.spyOn(ClientLibrary, 'startTouchEventTracker');
        startMotionSpy = vi.spyOn(ClientLibrary, 'startMotionTracker');
        startRenderingSpy = vi.spyOn(ClientLibrary, 'startRenderingTracker');
        initWasmSpy = vi.spyOn(ClientLibrary, 'initializeWasm').mockResolvedValue(undefined);
        initHoneypotsSpy = vi.spyOn(ClientLibrary, 'initializeHoneypots');
        injectTrapsSpy = vi.spyOn(ClientLibrary, 'injectTrapLinks');
        initFetchSpy = vi.spyOn(ClientLibrary, 'initializeFetch');
        window.fetch = (...args) => global.fetch(...args);
        injectPhantomTrapsSpy = vi.spyOn(ClientLibrary, 'injectPhantomTraps');
    });

    afterEach(() => {
        // Restaurer les espions après chaque test pour ne pas affecter les autres tests
        vi.restoreAllMocks();
    });

    it('should enable all trackers by default', () => {
        ClientLibrary.initializeClient();

        expect(startMouseSpy).toHaveBeenCalled();
        expect(startKeystrokeSpy).toHaveBeenCalled();
        expect(startClickSpy).toHaveBeenCalled();
        expect(startTouchSpy).toHaveBeenCalled();
        expect(startMotionSpy).toHaveBeenCalled();
        expect(startRenderingSpy).toHaveBeenCalled();
        expect(injectPhantomTrapsSpy).toHaveBeenCalled();
    });

    it('should disable trackers when configured', () => {
        ClientLibrary.initializeClient({ mouse: false, keystrokes: false, clicks: false, touches: false, motion: false, rendering: false });

        expect(startMouseSpy).not.toHaveBeenCalled();
        expect(startKeystrokeSpy).not.toHaveBeenCalled();
        expect(startClickSpy).not.toHaveBeenCalled();
        expect(startTouchSpy).not.toHaveBeenCalled();
        expect(startMotionSpy).not.toHaveBeenCalled();
        expect(startRenderingSpy).not.toHaveBeenCalled();
    });

    it('should initialize WASM if wasmPath is configured', () => {
        ClientLibrary.initializeClient({ wasmPath: '/fp.js' });

        expect(initWasmSpy).toHaveBeenCalledWith('/fp.js');
    });

    it('should disable phantom traps when configured', () => {
        ClientLibrary.initializeClient({ phantomTraps: false });

        expect(injectPhantomTrapsSpy).not.toHaveBeenCalled();
    });

    it('should initialize honeypots with the provided field names', () => {
        const honeypotFields = ['email_confirm', 'user_nickname'];
        ClientLibrary.initializeClient({ honeypots: honeypotFields });

        expect(initHoneypotsSpy).toHaveBeenCalledWith(honeypotFields);
    });

    it('should not initialize honeypots if the array is empty', () => {
        ClientLibrary.initializeClient({ honeypots: [] });

        expect(initHoneypotsSpy).not.toHaveBeenCalled();
    });

    it('should inject trap URLs when provided', () => {
        const urls = ['/trap1?sig=123', '/trap2?sig=456'];
        ClientLibrary.initializeClient({ trapUrls: urls });

        expect(injectTrapsSpy).toHaveBeenCalledWith(urls);
    });

    it('should not inject trap URLs if the array is empty', () => {
        ClientLibrary.initializeClient({ trapUrls: [] });

        expect(injectTrapsSpy).not.toHaveBeenCalled();
    });

    it('should initialize fetch interception when fetch config is present', () => {
        const targetDomains = ['api.example.com'];
        ClientLibrary.initializeClient({ fetch: { targetDomains } });

        expect(initFetchSpy).toHaveBeenCalledWith(targetDomains);
    });

    it('should not initialize fetch interception if fetch config is absent', () => {
        ClientLibrary.initializeClient(); // No fetch config

        expect(initFetchSpy).not.toHaveBeenCalled();
    });

    it('should call all initializers correctly when a full config is provided', () => {
        const config = {
            mouse: true,
            keystrokes: true,
            honeypots: ['field1'],
            trapUrls: ['/trap1'],
            fetch: { targetDomains: ['api.com'] }
        };
        ClientLibrary.initializeClient(config);

        expect(startMouseSpy).toHaveBeenCalled();
        expect(startKeystrokeSpy).toHaveBeenCalled();
        expect(initHoneypotsSpy).toHaveBeenCalledWith(config.honeypots);
        expect(injectTrapsSpy).toHaveBeenCalledWith(config.trapUrls);
        expect(initFetchSpy).toHaveBeenCalledWith(config.fetch.targetDomains);
    });

    it('should abort challenge retry loop when maxRetries is reached', async () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        const mockResponse = {
            status: 404,
            headers: new Headers({ 'content-type': 'application/json' }),
            bodyUsed: false,
            json: vi.fn().mockResolvedValue({
                challenge: { type: 'cpu_target', nonce: 'nonce-1', cpuTarget: '0000ffff' }
            }),
            clone() { return this; }
        };

        const result = await ClientLibrary.solveChallengeAndRetry(
            mockResponse,
            'http://localhost/api/data',
            { _powRetryCount: 3 },
            3
        );

        expect(result).toBe(mockResponse);
        expect(mockResponse.json).not.toHaveBeenCalled();
        expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Challenge retry limit reached (3)'));
    });

});