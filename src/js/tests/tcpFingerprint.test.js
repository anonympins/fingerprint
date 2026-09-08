import { describe, expect, it } from 'vitest';
import { __internal } from '../fingerprint.js';

const { parseTcpSyn, classifyTcpOs, getTcpAnomalyScore } = __internal;

describe('Passive TCP/IP Fingerprinting (Type p0f)', () => {
    
    // Mock d'un paquet IP + TCP SYN d'un système Linux (TTL=64, WS=7)
    const mockLinuxSynPacket = Buffer.from([
        0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x40, 0x00, 
        0x40, 0x06, 0x3c, 0x1a, 0x7f, 0x00, 0x00, 0x01, // TTL=0x40 (64)
        0x7f, 0x00, 0x00, 0x01, 
        0x1f, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, // Window=0x7210 (29200), TCP header len = 40 (0xa0)
        0x3c, 0x1a, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, // Option MSS: 1460 (0x05b4)
        0x04, 0x02,             // Option SACK Permitted
        0x01,                   // NOP
        0x03, 0x03, 0x07        // Option WS: 7
    ]);

    // Mock d'un paquet IP + TCP SYN d'un système Windows (TTL=128, WS=8)
    const mockWindowsSynPacket = Buffer.from([
        0x45, 0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x40, 0x00, 
        0x80, 0x06, 0x3c, 0x1a, 0x7f, 0x00, 0x00, 0x01, // TTL=0x80 (128)
        0x7f, 0x00, 0x00, 0x01, 
        0x1f, 0x90, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 
        0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xfa, 0xf0, // Window=64240 (0xfaf0)
        0x3c, 0x1a, 0x00, 0x00,
        0x02, 0x04, 0x05, 0xb4, // Option MSS: 1460 (0x05b4)
        0x04, 0x02,             // Option SACK Permitted
        0x01,                   // NOP
        0x03, 0x03, 0x08        // Option WS: 8
    ]);

    it('should correctly parse raw TCP SYN binary packets', () => {
        const linuxFp = parseTcpSyn(mockLinuxSynPacket);
        expect(linuxFp).not.toBeNull();
        expect(linuxFp.ttl).toBe(64);
        expect(linuxFp.windowSize).toBe(29200);
        expect(linuxFp.mss).toBe(1460);
        expect(linuxFp.ws).toBe(7);
        expect(linuxFp.sack).toBe(true);

        const windowsFp = parseTcpSyn(mockWindowsSynPacket);
        expect(windowsFp.ttl).toBe(128);
        expect(windowsFp.windowSize).toBe(64240);
        expect(windowsFp.ws).toBe(8);
    });

    it('should classify OS correctly based on parsed parameters', () => {
        const linuxFp = parseTcpSyn(mockLinuxSynPacket);
        expect(classifyTcpOs(linuxFp)).toBe('Linux');

        const windowsFp = parseTcpSyn(mockWindowsSynPacket);
        expect(classifyTcpOs(windowsFp)).toBe('Windows');
    });

    it('should calculate correct TCP/IP anomaly scores', () => {
        // Cas 1 : Le User-Agent prétend être Windows, mais la pile TCP/IP est Linux
        const contextAnomaly = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0',
            },
            rawTcpBinary: mockLinuxSynPacket
        };
        expect(getTcpAnomalyScore(contextAnomaly).tcpAnomalyScore).toBe(80);

        // Cas 2 : Cohérence complète (UA Windows et pile TCP/IP Windows)
        const contextCoherent = {
            headers: {
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0',
            },
            rawTcpBinary: mockWindowsSynPacket
        };
        expect(getTcpAnomalyScore(contextCoherent).tcpAnomalyScore).toBe(0);
    });
});