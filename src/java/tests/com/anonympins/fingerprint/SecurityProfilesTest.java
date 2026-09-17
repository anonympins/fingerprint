package com.anonympins.fingerprint;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Tests unitaires pour valider la parité et la logique de fusion des profils de sécurité.
 */
public class SecurityProfilesTest {

    @Test
    public void testPredefinedProfilesExist() {
        assertTrue(SecurityProfiles.PROFILES.containsKey("balanced"), "Le profil 'balanced' doit exister.");
        assertTrue(SecurityProfiles.PROFILES.containsKey("strict"), "Le profil 'strict' doit exister.");
        assertTrue(SecurityProfiles.PROFILES.containsKey("api"), "Le profil 'api' doit exister.");
        assertTrue(SecurityProfiles.PROFILES.containsKey("blog"), "Le profil 'blog' doit exister.");
    }

    @Test
    public void testCreateSecurityProfileDefaultFallback() {
        Map<String, Object> overrides = new HashMap<>();
        Map<String, Object> profile = SecurityProfiles.createSecurityProfile("unknown-profile", overrides);

        assertNotNull(profile, "Le profil retourné ne doit pas être nul.");
        assertEquals("Balanced Profile (Default)", profile.get("summary"), 
            "Un profil inconnu doit se rabattre sur le profil 'balanced' par défaut.");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testCreateSecurityProfileWithOverrides() {
        Map<String, Object> overrides = new HashMap<>();
        overrides.put("challengeNewDevices", false);
        overrides.put("wasm", false);

        // Surcharge imbriquée pour les poids de suspicion
        Map<String, Object> customWeights = new HashMap<>();
        customWeights.put("historyScore", 0.95);
        customWeights.put("ipReputationScore", 0.99); // Nouveau poids blog synchronisé
        overrides.put("weights", customWeights);

        Map<String, Object> profile = SecurityProfiles.createSecurityProfile("blog", overrides);

        // Vérification des surcharges au premier niveau
        assertEquals(false, profile.get("wasm"), "La surcharge globale de premier niveau 'wasm' doit être appliquée.");
        assertEquals(false, profile.get("challengeNewDevices"), "La surcharge de premier niveau doit être présente.");
        assertEquals("Blog Profile", profile.get("summary"), "Le profil de base doit rester le profil 'blog'.");

        // Vérification de la fusion imbriquée des poids (deepMerge)
        Map<String, Double> weights = (Map<String, Double>) profile.get("weights");
        assertNotNull(weights, "La map des poids ne doit pas être nulle.");
        assertEquals(0.95, weights.get("historyScore"), "Le poids 'historyScore' doit avoir été surchargé.");
        assertEquals(0.99, weights.get("ipReputationScore"), "Le nouveau poids 'ipReputationScore' doit avoir été surchargé.");
        
        // Vérification de la conservation des poids non surchargés du profil Blog
        assertEquals(0.8, weights.get("requestPatternScore"), "Les autres poids du profil de base doivent être conservés.");
        assertEquals(1.0, weights.get("honeypotScore"), "Les autres poids du profil de base doivent être conservés.");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testDeepMergeUtility() {
        // Target Map de base
        Map<String, Object> target = new HashMap<>();
        target.put("simpleKey", "originalValue");
        target.put("unaffectedKey", "keepMe");

        Map<String, Object> targetNested = new HashMap<>();
        targetNested.put("nestedKey1", "nestedOriginal1");
        targetNested.put("nestedKey2", "nestedOriginal2");
        target.put("nestedMap", targetNested);

        // Source Map contenant les surcharges
        Map<String, Object> source = new HashMap<>();
        source.put("simpleKey", "newValue");

        Map<String, Object> sourceNested = new HashMap<>();
        sourceNested.put("nestedKey1", "nestedNewValue1");
        source.put("nestedMap", sourceNested);

        // Exécution de la fusion
        Map<String, Object> result = SecurityProfiles.deepMerge(target, source);

        // Assertions de premier niveau
        assertEquals("newValue", result.get("simpleKey"), "La valeur de premier niveau doit être remplacée.");
        assertEquals("keepMe", result.get("unaffectedKey"), "La valeur non présente dans la source doit être conservée.");

        // Assertions imbriquées
        Map<String, Object> resultNested = (Map<String, Object>) result.get("nestedMap");
        assertNotNull(resultNested, "La map imbriquée fusionnée ne doit pas être nulle.");
        assertEquals("nestedNewValue1", resultNested.get("nestedKey1"), "La valeur imbriquée surchargée doit être appliquée.");
        assertEquals("nestedOriginal2", resultNested.get("nestedKey2"), "La valeur imbriquée non surchargée doit être conservée.");
    }

    @Test
    public void testBlogProfilePropertiesParity() {
        Map<String, Object> blogProfile = SecurityProfiles.PROFILES.get("blog");
        assertNotNull(blogProfile);

        @SuppressWarnings("unchecked")
        Map<String, Double> weights = (Map<String, Double>) blogProfile.get("weights");
        assertNotNull(weights);

        // Vérifie la présence et l'exactitude des nouvelles clés synchronisées
        assertEquals(0.3, weights.get("ipReputationScore"), "ipReputationScore doit être égal à 0.3");
        assertEquals(0.5, weights.get("botnetClusterScore"), "botnetClusterScore doit être égal à 0.5");
        assertEquals(0.5, weights.get("tcpAnomalyScore"), "tcpAnomalyScore doit être égal à 0.5");
        assertEquals(0.5, weights.get("quicAnomalyScore"), "quicAnomalyScore doit être égal à 0.5");
        assertEquals(0.5, weights.get("renderingAnomalyScore"), "renderingAnomalyScore doit être égal à 0.5");
    }
}