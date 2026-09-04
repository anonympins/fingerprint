import { describe, expect, it, vi, beforeEach } from 'vitest';
import { handleMetricsRequest } from '../src/js/fingerprint.js';

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