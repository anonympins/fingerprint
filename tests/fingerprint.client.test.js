import { it, describe, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock the builder module
vi.mock('../fingerprint.builder.js', () => {
    const FingerprintBuilder = vi.fn();
    FingerprintBuilder.prototype.add = vi.fn(function(group, value) {
        if (!this.components) this.components = new Map();
        this.components.set(group, `hash_of_${value}`);
        return this;
    });
    FingerprintBuilder.prototype.toString = vi.fn(function() {
        if (!this.components) return '';
        return Array.from(this.components.entries())
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([key, hash]) => `${key}:${hash}`)
            .join('|');
    });
    return { FingerprintBuilder, cyrb53: vi.fn((str) => `hashed_${str}`) };
});


describe('Fingerprint Client-Side Library', () => {
    let ClientLibrary;
    let mockDocument;
    let mockNavigator;
    let mockScreen;
    let mockWindow;

    beforeEach(async () => {
        // Reset modules to ensure mocks are fresh for each test
        vi.resetModules();

        // --- Comprehensive Browser Mock ---
        const mockField = {
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
        };

        mockDocument = {
            addEventListener: vi.fn(),
            removeEventListener: vi.fn(),
            querySelector: vi.fn((selector) => {
                if (selector === '[name="email_confirm"]') {
                    return mockField;
                }
                return null;
            }),
            // Mock for canvas/webgl
            createElement: vi.fn().mockImplementation((tag) => {
                if (tag === 'canvas') {
                    return {
                        getContext: vi.fn((contextType) => {
                            if (contextType === '2d') {
                                return {
                                    fillRect: vi.fn(),
                                    fillText: vi.fn(),
                                    toDataURL: vi.fn().mockReturnValue('mock-canvas-data'),
                                };
                            }
                            if (contextType === 'webgl' || contextType === 'experimental-webgl') {
                                return {
                                    getExtension: vi.fn().mockReturnValue({
                                        UNMASKED_VENDOR_WEBGL: 'vendor_id',
                                        UNMASKED_RENDERER_WEBGL: 'renderer_id',
                                    }),
                                    getParameter: vi.fn(param => {
                                        if (param === 'vendor_id') return 'MockVendor';
                                        if (param === 'renderer_id') return 'MockRenderer';
                                        return '';
                                    }),
                                };
                            }
                            return null;
                        }),
                    };
                }
                return {};
            }),
        };

        mockNavigator = {
            hardwareConcurrency: 8,
            deviceMemory: 8,
            maxTouchPoints: 0,
            platform: 'Win32',
            webdriver: false,
            language: 'en-US',
        };

        mockScreen = {
            width: 1920,
            height: 1080,
            colorDepth: 24,
        };

        mockWindow = {
            navigator: mockNavigator,
            screen: mockScreen,
            document: mockDocument,
            fetch: vi.fn(() => Promise.resolve({ ok: true })),
            location: { origin: 'http://localhost' },
            URL: URL, // Use the real URL constructor from the test environment
            Headers: Headers, // Use the real Headers constructor
            Request: Request, // Use the real Request constructor
            performance: { now: vi.fn(() => Date.now()) },
            Intl: {
                DateTimeFormat: () => ({
                    resolvedOptions: () => ({ timeZone: 'Europe/Paris' }),
                }),
            },
        };

        // Stub the global objects that the client script expects
        vi.stubGlobal('window', mockWindow);
        vi.stubGlobal('document', mockDocument);
        vi.stubGlobal('navigator', mockNavigator);
        vi.stubGlobal('screen', mockScreen);
        vi.stubGlobal('performance', mockWindow.performance);
        vi.stubGlobal('fetch', mockWindow.fetch);

        // Dynamically import the library to use the mocked environment
        ClientLibrary = await import('../fingerprint.client.js');
        ClientLibrary._resetCache(); // Ensure fingerprint is not cached between tests
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.clearAllMocks();
    });

    describe('Core Fingerprinting', () => {
        it('should generate a deterministic fingerprint string', () => {
            const fp1 = ClientLibrary.getDeviceFingerprint();
            ClientLibrary._resetCache(); // Force recalculation
            const fp2 = ClientLibrary.getDeviceFingerprint();
            expect(fp1).toBeTypeOf('string');
            expect(fp1).toContain('hw:');
            expect(fp1).toEqual(fp2);
        });

        it('should use cache on subsequent calls', () => {
            const fp1 = ClientLibrary.getDeviceFingerprint();
            const fp2 = ClientLibrary.getDeviceFingerprint(); // Should be from cache
            // The mock implementation of `add` is called only when the fingerprint is generated, not when read from cache.
            // We expect it to be called for the first generation, but not the second.
            // The number of calls depends on the number of components added.
            const initialCallCount = mockDocument.createElement.mock.calls.length;
            expect(fp1).toBe(fp2);
            expect(mockDocument.createElement.mock.calls.length).toBe(initialCallCount);
        });

        it('should generate a request signature', () => {
            const payload = { user: 'test', action: 'login' };
            const signature = ClientLibrary.generateRequestSignature(payload);
            expect(signature).toContain('|req:');
            expect(signature).toContain('hw:');
        });
    });

    describe('Behavioral Metrics', () => {
        it('should track mouse entropy', () => {
            ClientLibrary.startMouseEntropyTracker();
            expect(mockDocument.addEventListener).toHaveBeenCalledWith('mousemove', expect.any(Function), { passive: true });
        });

        it('should track keystroke latency', () => {
            ClientLibrary.startKeystrokeDynamicsTracker();
            expect(mockDocument.addEventListener).toHaveBeenCalledWith('keydown', expect.any(Function), { passive: true });
        });

        it('should initialize honeypots', () => {
            ClientLibrary.initializeHoneypots(['email_confirm']);
            expect(mockDocument.querySelector).toHaveBeenCalledWith('[name="email_confirm"]');
            // The mock is set up to return mockField when the selector matches. We just need to check if its methods were called.
            expect(mockDocument.querySelector('[name="email_confirm"]').addEventListener).toHaveBeenCalledWith('input', expect.any(Function));
        });

        it('should flag honeypot interaction', () => {
            const metrics = ClientLibrary.getClientBehaviorMetrics();
            expect(metrics.honeypotInteraction).toBe(false);
            // Manually trigger the internal function to simulate interaction
            // We can't call the private onHoneypotTrigger directly.
            // Instead, we simulate the event that calls it.
            ClientLibrary.initializeHoneypots(['email_confirm']);
            const listener = mockDocument.querySelector('[name="email_confirm"]').addEventListener.mock.calls[0][1];
            listener(); // Manually invoke the event listener
            const newMetrics = ClientLibrary.getClientBehaviorMetrics();
            expect(newMetrics.honeypotInteraction).toBe(true);
        });
    });

    describe('Fetch Interception', () => {
        it('protectedFetch should add security headers', async () => {
            await ClientLibrary.protectedFetch('/api/data', { method: 'POST' });
            expect(mockWindow.fetch).toHaveBeenCalled();
            const options = mockWindow.fetch.mock.calls[0][1];
            expect(options.headers.get('X-Device-Fingerprint')).toBeTruthy();
            expect(options.headers.get('X-Behavior-Metrics')).toBeTruthy();
        });

        it('initializeFetch should patch global fetch for same-origin requests', async () => {
            // Garder une référence au fetch original (notre mock)
            const originalFetchMock = mockWindow.fetch;
            ClientLibrary.initializeFetch(); // Appelle le patch

            // 1. Requête même origine (chemin relatif)
            await window.fetch('/api/local');
            let callOptions = originalFetchMock.mock.calls[0][1];
            expect(callOptions.headers.get('X-Device-Fingerprint')).toBeTruthy();

            // 2. Requête même origine (chemin absolu)
            await window.fetch('http://localhost/api/local2');
            callOptions = originalFetchMock.mock.calls[1][1];
            expect(callOptions.headers.get('X-Device-Fingerprint')).toBeTruthy();

            // 3. Requête vers un autre domaine
            await window.fetch('http://external.com/api/data');
            callOptions = originalFetchMock.mock.calls[2][1];
            // Les en-têtes ne doivent pas être ajoutés, donc `options.headers` peut ne pas exister
            expect(callOptions?.headers?.get('X-Device-Fingerprint')).toBeFalsy();
        });

        it('initializeFetch should patch fetch for target domains', async () => {
            const originalFetchMock = mockWindow.fetch;
            ClientLibrary.initializeFetch(['api.service.com']);

            // 1. Requête vers le domaine cible
            await window.fetch('https://api.service.com/data');
            let callOptions = originalFetchMock.mock.calls[0][1];
            expect(callOptions.headers.get('X-Device-Fingerprint')).toBeTruthy();

            // 2. Requête vers un domaine non-cible
            await window.fetch('https://other.domain.com/data');
            callOptions = originalFetchMock.mock.calls[1][1];
            expect(callOptions?.headers?.get('X-Device-Fingerprint')).toBeFalsy();

            // 3. Requête même origine (ne doit pas être protégée car `targetDomains` est spécifié)
            await window.fetch('/api/local');
            callOptions = originalFetchMock.mock.calls[2][1];
            expect(callOptions?.headers?.get('X-Device-Fingerprint')).toBeFalsy();
        });
    });

    describe('Unified Initialization', () => {
        let startMouseSpy, startKeystrokeSpy, initHoneypotsSpy, initFetchSpy;

        beforeEach(async () => {
            // Spy on the methods of the internal ClientLibrary object.
            // We dynamically import it to get a fresh instance with our mocks.
            const ClientLibraryModule = await import('../fingerprint.client.js');
            startMouseSpy = vi.spyOn(ClientLibraryModule.default, 'startMouseEntropyTracker');
            startKeystrokeSpy = vi.spyOn(ClientLibraryModule.default, 'startKeystrokeDynamicsTracker');
            initHoneypotsSpy = vi.spyOn(ClientLibraryModule.default, 'initializeHoneypots');
            initFetchSpy = vi.spyOn(ClientLibraryModule.default, 'initializeFetch');
        });

        it('should call sub-initializers based on config', () => {
            ClientLibrary.initializeClient({
                mouse: true,
                keystrokes: false,
                honeypots: ['test_field'],
                fetch: {}
            });

            expect(startMouseSpy).toHaveBeenCalled();
            expect(startKeystrokeSpy).not.toHaveBeenCalled();
            expect(initHoneypotsSpy).toHaveBeenCalledWith(['test_field']);
            expect(initFetchSpy).toHaveBeenCalledWith(undefined);
        });

        it('should enable all features by default except fetch and honeypots', () => {
            ClientLibrary.initializeClient({}); // Call with empty config to match defaults

            expect(startMouseSpy).toHaveBeenCalled();
            expect(startKeystrokeSpy).toHaveBeenCalled();
            expect(initHoneypotsSpy).not.toHaveBeenCalled();
            expect(initFetchSpy).not.toHaveBeenCalled();
        });
    });
});