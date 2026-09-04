import {describe, expect, it} from 'vitest';
import {Optimization} from '../src/js/library.js';

describe('Optimization.Operators.benfordTest', () => {

    it('should return 0 for non-array inputs', () => {
        expect(Optimization.Operators.benfordTest("12345")).toBe(0);
        expect(Optimization.Operators.benfordTest(null)).toBe(0);
        expect(Optimization.Operators.benfordTest(undefined)).toBe(0);
        expect(Optimization.Operators.benfordTest({ a: 1 })).toBe(0);
    });

    it('should return 0 for arrays with less than 10 valid numbers', () => {
        const smallArray = [1, 2, 3, 4, 5, 6, 7, 8, 9];
        expect(Optimization.Operators.benfordTest(smallArray)).toBe(0);
    });

    it('should return 0 for an empty array', () => {
        expect(Optimization.Operators.benfordTest([])).toBe(0);
    });

    it('should ignore zeros, non-numeric strings, and leading spaces', () => {
        // This array contains only 9 valid leading digits.
        const dirtyArray = [0, " 123", "abc", 2, 3, 4, 5, 6, 7, 8, 9, null, undefined];
        expect(Optimization.Operators.benfordTest(dirtyArray)).toBe(0);
    });

    it('should return a very low score for a distribution that perfectly matches Benford\'s law', () => {
        // Création d'un échantillon de 1000 nombres qui suit la loi de Benford
        const benfordSample = [
            ...Array(301).fill(100), // 301 nombres commençant par 1
            ...Array(176).fill(200), // 176 nombres commençant par 2
            ...Array(125).fill(300), // 125 nombres commençant par 3
            ...Array(97).fill(400),  // etc.
            ...Array(79).fill(500),
            ...Array(67).fill(600),
            ...Array(58).fill(700),
            ...Array(51).fill(800),
            ...Array(46).fill(900),
        ];

        const score = Optimization.Operators.benfordTest(benfordSample);
        // Le score devrait être très proche de 0. On utilise toBeLessThan pour tolérer les imprécisions de calcul.
        expect(score).toBeLessThan(1e-9);
    });

    it('should return a high (suspect) score for a uniform distribution', () => {
        // Une distribution uniforme est très peu naturelle pour ce genre de données.
        const uniformSample = [];
        for (let i = 1; i <= 9; i++) {
            for (let j = 0; j < 100; j++) {
                uniformSample.push(i * 100 + j);
            }
        }

        const score = Optimization.Operators.benfordTest(uniformSample);
        // Un score > 0.15 est considéré comme suspect.
        expect(score).toBeGreaterThan(0.15);
    });

    it('should return a high (suspect) score for a distribution skewed towards high digits', () => {
        // L'inverse de la loi de Benford, très suspect.
        const inverseBenfordSample = [
            ...Array(46).fill(100),
            ...Array(51).fill(200),
            ...Array(58).fill(300),
            ...Array(67).fill(400),
            ...Array(79).fill(500),
            ...Array(97).fill(600),
            ...Array(125).fill(700),
            ...Array(176).fill(800),
            ...Array(301).fill(900),
        ];

        const score = Optimization.Operators.benfordTest(inverseBenfordSample);
        expect(score).toBeGreaterThan(0.3); // Score attendu encore plus élevé
    });

    it('should handle real-world-like data (request timings)', () => {
        // Simule des délais de requêtes générés par un bot (ex: aléatoire uniforme entre 500 et 1500ms)
        const botTimings = Array.from({ length: 100 }, () => 500 + Math.random() * 1000);
        const botScore = Optimization.Operators.benfordTest(botTimings);

        // Simule des délais humains (plus de petits délais, quelques longs délais)
        const humanTimings = [
            123, 234, 180, 345, 150, 456, 110, 190, 210, 280, 567, 130, 890, 1200, 310, 160
        ];
        const humanScore = Optimization.Operators.benfordTest(humanTimings);

        // Le score du bot devrait être significativement plus élevé que celui de l'humain.
        // Les valeurs exactes peuvent varier, mais la tendance doit être claire.
        expect(botScore).toBeGreaterThan(0.1);
        expect(humanScore).toBeLessThan(botScore);
    });

});