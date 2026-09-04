import { describe, expect, it, vi, beforeEach } from 'vitest';
import { handleMetricsRequest, __internal } from '../src/js/fingerprint.js';

describe('Metrics & Authorization Callback Integration', () => {
    let req, res;

    beforeEach(() => {
        req = {
            ip: '127.0.0.1',
            path: '/metrics',
            headers: { 'user-agent': 'prometheus' },
            query: {},
            body: {},
            cookies: {},
            httpVersion: '1.1'
        };
        res = {
            status: vi.fn().mockReturnThis(),
            send: vi.fn().mockReturnThis(),
            set: vi.fn().mockReturnThis(),
            redirect: vi.fn().mockReturnThis()
        };
    });
    it('should return metrics with 200 Content-Type if authorized', async () => {
        const config = {
            metricsAuthorizationCallback: () => true
        };
        await handleMetricsRequest(req, res, config);

        expect(res.set).toHaveBeenCalledWith('Content-Type', expect.stringContaining('text/plain'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_requests_total'));
    });

    it('should include current weights and thresholds in prometheus metrics output', async () => {
        const config = {
            metricsAuthorizationCallback: () => true,
            weights: { historyScore: 0.35, rotationScore: 0.65 },
            thresholds: { low: 22, block: 92 }
        };
        await handleMetricsRequest(req, res, config);

        expect(res.set).toHaveBeenCalledWith('Content-Type', expect.stringContaining('text/plain'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_security_weight{indicator="historyScore"} 0.35'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_security_weight{indicator="rotationScore"} 0.65'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_security_threshold{level="low"} 22'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_security_threshold{level="block"} 92'));
    });

    it('should include auto-tuning performance metrics if a best solution is available', async () => {
        __internal.setLastBestSolution({
            solution: {},
            objectives: [0.0123, 0.0456]
        });

        const config = {
            metricsAuthorizationCallback: () => true
        };
        await handleMetricsRequest(req, res, config);

        expect(res.set).toHaveBeenCalledWith('Content-Type', expect.stringContaining('text/plain'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_autotuning_false_positive_rate 0.0123'));
        expect(res.send).toHaveBeenCalledWith(expect.stringContaining('fingerprint_autotuning_false_negative_rate 0.0456'));

        // Cleanup
        __internal.setLastBestSolution(null);
    });

    it('should return 403 if authorization callback returns false', async () => {
        const config = {
            metricsAuthorizationCallback: () => false
        };
        await handleMetricsRequest(req, res, config);

        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.send).toHaveBeenCalledWith('Access to metrics denied.');
    });

    it('should handle custom block action returned by authorization callback', async () => {
        const config = {
            metricsAuthorizationCallback: () => ({
                action: 'block',
                status: 401,
                body: 'Custom unauthorized message'
            })
        };
        await handleMetricsRequest(req, res, config);

        expect(res.status).toHaveBeenCalledWith(401);
        expect(res.send).toHaveBeenCalledWith('Custom unauthorized message');
    });

    it('should handle custom redirect action returned by authorization callback', async () => {
        const config = {
            metricsAuthorizationCallback: () => ({
                action: 'redirect',
                status: 302,
                path: '/forbidden'
            })
        };
        await handleMetricsRequest(req, res, config);

        expect(res.redirect).toHaveBeenCalledWith(302, '/forbidden');
    });
});