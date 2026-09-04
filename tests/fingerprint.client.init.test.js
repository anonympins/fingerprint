import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';
import {JSDOM} from 'jsdom';
import ClientLibrary from '../src/js/fingerprint.client.js';

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

global.fetch = vi.fn(); // Mock global fetch
global.Headers = dom.window.Headers;
global.Request = dom.window.Request;
global.URL = dom.window.URL;
global.TextEncoder = dom.window.TextEncoder;


describe('ClientLibrary.initializeClient', () => {

    // On utilise des espions (spies) pour vérifier si les méthodes internes sont appelées.
    let startMouseSpy, startKeystrokeSpy, initHoneypotsSpy, injectTrapsSpy, initFetchSpy;

    beforeEach(() => {
        // Réinitialiser l'état du client avant chaque test
        ClientLibrary._resetCache();

        // Créer les espions sur les méthodes internes
        startMouseSpy = vi.spyOn(ClientLibrary, 'startMouseEntropyTracker');
        startKeystrokeSpy = vi.spyOn(ClientLibrary, 'startKeystrokeDynamicsTracker');
        initHoneypotsSpy = vi.spyOn(ClientLibrary, 'initializeHoneypots');
        injectTrapsSpy = vi.spyOn(ClientLibrary, 'injectTrapLinks');
        initFetchSpy = vi.spyOn(ClientLibrary, 'initializeFetch');
    });

    afterEach(() => {
        // Restaurer les espions après chaque test pour ne pas affecter les autres tests
        vi.restoreAllMocks();
    });

    it('should enable all trackers by default', () => {
        ClientLibrary.initializeClient();

        expect(startMouseSpy).toHaveBeenCalled();
        expect(startKeystrokeSpy).toHaveBeenCalled();
    });

    it('should disable mouse and keystroke trackers when configured', () => {
        ClientLibrary.initializeClient({ mouse: false, keystrokes: false });

        expect(startMouseSpy).not.toHaveBeenCalled();
        expect(startKeystrokeSpy).not.toHaveBeenCalled();
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

});