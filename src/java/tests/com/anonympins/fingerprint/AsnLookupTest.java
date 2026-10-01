package com.anonympins.fingerprint;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AsnLookupTest {

    private final AsnLookupEngine engine = AsnLookupEngine.getInstance();

    @Test
    public void testDatacenterResolutionAndPriorScore() {
        // Hetzner
        NetworkProfile hetzner = engine.lookup("95.216.12.34");
        assertEquals("HOSTING", hetzner.getType());
        assertEquals(55.0, hetzner.getBaseScore());
        assertEquals(0.85, hetzner.getInflectionPoint());
        assertFalse(hetzner.isToleranceRotation());

        // AWS
        NetworkProfile aws = engine.lookup("54.210.1.20");
        assertEquals("HOSTING", aws.getType());
        assertEquals(55.0, aws.getBaseScore());
    }

    @Test
    public void testMobileCgnatResolution() {
        NetworkProfile cgnat = engine.lookup("100.70.1.25");
        assertEquals("CELLULAR", cgnat.getType());
        assertEquals(10.0, cgnat.getBaseScore());
        assertEquals(0.60, cgnat.getInflectionPoint());
        assertTrue(cgnat.isToleranceRotation());
    }

    @Test
    public void testStarlinkSatelliteResolution() {
        NetworkProfile starlink = engine.lookup("98.97.10.5");
        assertEquals("SATELLITE", starlink.getType());
        assertEquals(15.0, starlink.getBaseScore());
        assertEquals(150.0, starlink.getJitterTolerance());
    }

    @Test
    public void testResidentialDefault() {
        NetworkProfile res = engine.lookup("82.120.45.67");
        assertEquals("RESIDENTIAL", res.getType());
        assertEquals(0.0, res.getBaseScore());
        assertEquals(0.72, res.getInflectionPoint());
    }

    @Test
    public void testAnalogInconsistencyModulation() {
        double consistency = 0.80; // Incohérence légère de rendu
        double scoreDatacenter = FingerprintEngine.calculateAnalogInconsistencyScore(consistency, NetworkProfile.HOSTING.getInflectionPoint(), 12.0);
        double scoreMobile = FingerprintEngine.calculateAnalogInconsistencyScore(consistency, NetworkProfile.CELLULAR.getInflectionPoint(), 12.0);

        assertTrue(scoreDatacenter > 55.0, "Sur Datacenter (0.80 < 0.85), la suspicion décolle au-dessus de 55.0");
        assertTrue(scoreMobile < 10.0, "Sur Mobile (0.80 > 0.60), la variation est entièrement absorbée (< 10.0)");
    }
}