package com.anonympins.fingerprint;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Map;

public class FingerprintPropertiesTest {

    @Test
    public void testDefaultThresholdsMapConversion() {
        FingerprintProperties.Thresholds thresholds = new FingerprintProperties.Thresholds();
        assertEquals(20, thresholds.getLow());
        assertEquals(45, thresholds.getMedium());
        assertEquals(75, thresholds.getHigh());
        assertEquals(95, thresholds.getBlock());

        Map<String, Object> map = thresholds.toMap();
        assertEquals(20, map.get("low"));
        assertEquals(45, map.get("medium"));
        assertEquals(75, map.get("high"));
        assertEquals(95, map.get("block"));
    }

    @Test
    public void testDefaultCpuMapConversion() {
        FingerprintProperties.Cpu cpu = new FingerprintProperties.Cpu();
        assertEquals(8, cpu.getMinDifficultyBits());
        assertEquals(22, cpu.getMaxDifficultyBits());

        Map<String, Object> map = cpu.toMap();
        assertEquals(8, map.get("minDifficultyBits"));
        assertEquals(22, map.get("maxDifficultyBits"));
    }

    @Test
    public void testDefaultPospaceMapConversion() {
        FingerprintProperties.Pospace pospace = new FingerprintProperties.Pospace();
        assertEquals(100, pospace.getSizeMb());
        assertEquals(10, pospace.getNumQueries());
        assertEquals(15, pospace.getCoopTimeout());

        Map<String, Object> map = pospace.toMap();
        assertEquals(100, map.get("sizeMb"));
        assertEquals(10, map.get("numQueries"));
        assertEquals(15, map.get("coopTimeout"));
    }

    @Test
    public void testWhitelistRuleMapConversion() {
        FingerprintProperties.WhitelistRule rule = new FingerprintProperties.WhitelistRule();
        rule.setType("path_allowlist");
        rule.getEntries().add("/assets/*");
        rule.setHostnameSuffix(".googlebot.com");

        Map<String, Object> map = rule.toMap();
        assertEquals("path_allowlist", map.get("type"));
        assertTrue(((java.util.List<?>) map.get("entries")).contains("/assets/*"));
        assertEquals(".googlebot.com", map.get("hostnameSuffix"));
        assertNull(map.get("userAgent")); // Ne doit pas être présent si null
    }
}