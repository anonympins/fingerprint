package com.anonympins.fingerprint;

/**
 * Profils de connectivité réseau et paramètres de modulation pour le scoring analogique.
 */
public enum NetworkProfile {
    RESIDENTIAL("RESIDENTIAL", 0.0, 0.72, false, 60.0),
    CELLULAR("CELLULAR", 10.0, 0.60, true, 80.0),
    SATELLITE("SATELLITE", 15.0, 0.68, false, 150.0),
    HOSTING("HOSTING", 55.0, 0.85, false, 30.0),
    ANONYMIZER("ANONYMIZER", 85.0, 0.90, false, 40.0);

    private final String type;
    private final double baseScore;
    private final double inflectionPoint;
    private final boolean toleranceRotation;
    private final double jitterTolerance;

    NetworkProfile(String type, double baseScore, double inflectionPoint, boolean toleranceRotation, double jitterTolerance) {
        this.type = type;
        this.baseScore = baseScore;
        this.inflectionPoint = inflectionPoint;
        this.toleranceRotation = toleranceRotation;
        this.jitterTolerance = jitterTolerance;
    }

    public String getType() { return type; }

    /** Prior bayésien (R_0) appliqué instantanément sans attendre l'historique */
    public double getBaseScore() { return baseScore; }

    /** Point d'inflexion x_0 de la sigmoïde analogique */
    public double getInflectionPoint() { return inflectionPoint; }

    /** Indique si la rotation d'IP est tolérée (CGNAT mobile) */
    public boolean isToleranceRotation() { return toleranceRotation; }

    public double getJitterTolerance() { return jitterTolerance; }
}