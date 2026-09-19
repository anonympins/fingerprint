import { describe, expect, it } from 'vitest';
import { __internal } from '../fingerprint.js';

const { getProtocolAnomalyScore } = __internal;

describe('Protocol Anomaly Flow Profiling', () => {
    it('should return 0.0 if no QUIC or HTTP/2 fingerprint is present', () => {
        const context = { headers: {} };
        const score = getProtocolAnomalyScore(context);
        expect(score.protocolAnomalyScore).toBe(0.0);
    });

    it('should detect Chrome spoofed with non-default stream/priority values (QUIC)', () => {
        // Chrome attend un initial_max_data (1) >= 1MB, initial_max_streams_bidi (4) == 100, et extensible Priority (contient u=)
        const context = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-quic-fp': '1;1=65536,4=50;i=0' // max_data trop bas, max_streams != 100, pas de priorité u=
            }
        };
        const score = getProtocolAnomalyScore(context);
        expect(score.protocolAnomalyScore).toBe(100.0);
    });

    it('should return 0.0 for a legitimate Chrome QUIC flow profile', () => {
        const context = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-quic-fp': '1;1=1572864,4=100;u=2,i'
            }
        };
        const score = getProtocolAnomalyScore(context);
        expect(score.protocolAnomalyScore).toBe(0.0);
    });

    it('should detect Chromium HTTP/2 header order anomalies', () => {
        const context = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-http2-fingerprint': '1|65535|0|invalid_order'
            }
        };
        const score = getProtocolAnomalyScore(context);
        expect(score.protocolAnomalyScore).toBe(100.0);
    });
});