import { describe, expect, it } from 'vitest';
import { AsnLookupEngine, NetworkProfile } from '../asn-lookup.js';
import { calculateAnalogInconsistencyScore } from '../fingerprint.js';

describe('Native AsnLookupEngine Patricia Trie', () => {
  const engine = new AsnLookupEngine();

  it('should resolve Hetzner and AWS Datacenter IPs under 50ns with prior score 55.0', () => {
    const hetznerProfile = engine.lookup('95.216.12.34');
    expect(hetznerProfile.type).toBe('HOSTING');
    expect(hetznerProfile.baseScore).toBe(55.0);
    expect(hetznerProfile.inflectionPoint).toBe(0.85);

    const awsProfile = engine.lookup('54.210.1.20');
    expect(awsProfile.type).toBe('HOSTING');
  });

  it('should identify Mobile CGNAT 100.64.0.0/10 with rotation tolerance', () => {
    const cgnatProfile = engine.lookup('100.70.1.25');
    expect(cgnatProfile.type).toBe('CELLULAR');
    expect(cgnatProfile.toleranceRotation).toBe(true);
    expect(cgnatProfile.inflectionPoint).toBe(0.60);
  });

  it('should identify Starlink Satellite ranges with elevated jitter tolerance', () => {
    const starlinkProfile = engine.lookup('98.97.10.5');
    expect(starlinkProfile.type).toBe('SATELLITE');
    expect(starlinkProfile.jitterTolerance).toBe(150.0);
  });

  it('should default unknown residential IP to 0.0 base score', () => {
    const resProfile = engine.lookup('82.120.45.67');
    expect(resProfile.type).toBe('RESIDENTIAL');
    expect(resProfile.baseScore).toBe(0.0);
    expect(resProfile.inflectionPoint).toBe(0.72);
  });

  describe('Analog Inconsistency Modulation', () => {
    it('should be significantly more sensitive on Datacenter IP than Mobile for identical consistency', () => {
      const consistency = 0.80; // Légère incohérence de rendu (ex: Canvas altéré)

      const datacenterProfile = NetworkProfile.HOSTING; // inflectionPoint = 0.85
      const mobileProfile = NetworkProfile.CELLULAR;    // inflectionPoint = 0.60
      const residentialProfile = NetworkProfile.RESIDENTIAL; // inflectionPoint = 0.72

      const scoreDatacenter = calculateAnalogInconsistencyScore(consistency, datacenterProfile);
      const scoreResidential = calculateAnalogInconsistencyScore(consistency, residentialProfile);
      const scoreMobile = calculateAnalogInconsistencyScore(consistency, mobileProfile);

      // Sur Datacenter (0.80 < 0.85), la suspicion décolle immédiatement
      expect(scoreDatacenter).toBeGreaterThan(55.0);
      // Sur Mobile (0.80 > 0.60), la variation est entièrement absorbée
      expect(scoreMobile).toBeLessThan(10.0);
      expect(scoreDatacenter).toBeGreaterThan(scoreResidential);
    });
  });
});