import { describe, expect, it } from 'vitest';
import { __internal } from '../fingerprint.js';

const { getQuicAnomalyScore } = __internal;

describe('QUIC / HTTP/3 Flow Profiling', () => {
    it('should return 0.0 if no QUIC fingerprint is present', () => {
        const context = { headers: {} };
        const score = getQuicAnomalyScore(context);
        expect(score.quicAnomalyScore).toBe(0.0);
    });

    it('should detect Chrome spoofed with non-default stream/priority values', () => {
        // Chrome attend un initial_max_data (1) >= 1MB, initial_max_streams_bidi (4) == 100, et extensible Priority (contient u=)
        const context = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-quic-fp': '1;1=65536,4=50;i=0' // max_data trop bas, max_streams != 100, pas de priorité u=
            }
        };
        const score = getQuicAnomalyScore(context);
        expect(score.quicAnomalyScore).toBe(100.0);
    });

    it('should return 0.0 for a legitimate Chrome QUIC flow profile', () => {
        const context = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'x-quic-fp': '1;1=1572864,4=100;u=2,i'
            }
        };
        const score = getQuicAnomalyScore(context);
        expect(score.quicAnomalyScore).toBe(0.0);
    });
});