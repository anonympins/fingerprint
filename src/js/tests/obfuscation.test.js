import { describe, expect, it } from 'vitest';
import { __internal } from '../fingerprint.js';

describe('Système de Polymorphisme et Compilateur d\'Obfuscation', () => {
    
    it('should generate a valid session mapping with randomized headers and globals', () => {
        const mapping1 = __internal.generateSessionMapping();
        const mapping2 = __internal.generateSessionMapping();

        // Vérification de la présence des structures attendues
        expect(mapping1).toBeDefined();
        expect(mapping1.headers).toHaveProperty('x-device-fingerprint');
        expect(mapping1.headers).toHaveProperty('x-behavior-metrics');
        expect(mapping1.globals).toHaveProperty('ClientLibrary');
        expect(mapping1.globals).toHaveProperty('getDeviceFingerprint');
        expect(mapping1.globals).toHaveProperty('getClientBehaviorMetrics');
        expect(mapping1.keys).toHaveProperty('ua');
        expect(mapping1.wasmConstants).toHaveProperty('seed');

        // Vérification de l'aléa (deux sessions consécutives doivent avoir des mappings uniques)
        expect(mapping1.headers['x-device-fingerprint']).not.toBe(mapping2.headers['x-device-fingerprint']);
        expect(mapping1.globals['ClientLibrary']).not.toBe(mapping2.globals['ClientLibrary']);
        expect(mapping1.keys['ua']).not.toBe(mapping2.keys['ua']);
        expect(mapping1.wasmConstants.seed).not.toBe(mapping2.wasmConstants.seed);
    });

    it('should compile and obfuscate client script asynchronously using the obfuscation worker', async () => {
        const mapping = __internal.generateSessionMapping();
        
        // On lance la compilation lourde qui instancie le Worker d'arrière-plan
        const obfuscatedCode = await __internal.compilePolymorphicJs(mapping);

        expect(obfuscatedCode).toBeDefined();
        expect(typeof obfuscatedCode).toBe('string');
        expect(obfuscatedCode.length).toBeGreaterThan(0);

        // Vérification que les placeholders originaux ont bien été purgés du code client final
        expect(obfuscatedCode).not.toContain('X-Device-Fingerprint');
        expect(obfuscatedCode).not.toContain('X-Behavior-Metrics');
        expect(obfuscatedCode).not.toContain('ClientLibrary');

        // Vérification que le code est minifié/obfusqué (ne contient pas de commentaires de développement par exemple)
        expect(obfuscatedCode).not.toContain('// Nom trompeur aléatoire pour attirer les analyseurs');
        
        // La structure globale de javascript-obfuscator génère typiquement un tableau de chaînes au début
        expect(obfuscatedCode).toMatch(/_0x/);
    }, 15000); // Augmentation du timeout à 15s car l'obfuscation via Worker thread consomme du CPU
});