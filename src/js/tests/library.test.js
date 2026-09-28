import {describe, expect, it} from 'vitest';
import {Optimization} from '../library.js';

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
        // Sample of 1000 numbers matching Benford's Law distribution
        const benfordSample = [
            ...Array(301).fill(100), // 301 numbers leading with 1
            ...Array(176).fill(200), // 176 numbers leading with 2
            ...Array(125).fill(300), // 125 numbers leading with 3
            ...Array(97).fill(400),  // etc.
            ...Array(79).fill(500),
            ...Array(67).fill(600),
            ...Array(58).fill(700),
            ...Array(51).fill(800),
            ...Array(46).fill(900),
        ];

        const score = Optimization.Operators.benfordTest(benfordSample);
        // Score should be close to 0; tolerance used for floating point variance
        expect(score).toBeLessThan(1e-9);
    });

    it('should return a high (suspect) score for a uniform distribution', () => {
        // Uniform distribution is unnatural for this category of metrics
        const uniformSample = [];
        for (let i = 1; i <= 9; i++) {
            for (let j = 0; j < 100; j++) {
                uniformSample.push(i * 100 + j);
            }
        }

        const score = Optimization.Operators.benfordTest(uniformSample);
        // A score > 0.15 is considered suspicious
        expect(score).toBeGreaterThan(0.15);
    });

    it('should return a high (suspect) score for a distribution skewed towards high digits', () => {
        // Inverted Benford distribution: highly unnatural
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
        expect(score).toBeGreaterThan(0.3); // Significantly elevated score expected
    });

    it('should handle real-world-like data (request timings)', () => {
        // Simulates bot request intervals (uniform random between 500 and 1500ms)
        const botTimings = Array.from({ length: 100 }, () => 500 + Math.random() * 1000);
        const botScore = Optimization.Operators.benfordTest(botTimings);

        // Simulates human timings (more short delays, few long pauses)
        const humanTimings = [
            123, 234, 180, 345, 150, 456, 110, 190, 210, 280, 567, 130, 890, 1200, 310, 160
        ];
        const humanScore = Optimization.Operators.benfordTest(humanTimings);

        // Bot score should be significantly higher than human score
        expect(botScore).toBeGreaterThan(0.1);
        expect(humanScore).toBeLessThan(botScore);
    });

});