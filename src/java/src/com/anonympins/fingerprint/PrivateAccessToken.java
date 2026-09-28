package com.anonympins.fingerprint;

/**
 * Structure binaire d'un Private Access Token (RFC 9578 Section 2.1).
 * 
 * Structure :
 * - uint16_t token_type (2 octets)
 * - uint8_t nonce[32] (32 octets)
 * - uint8_t challenge_digest[32] (32 octets)
 * - uint8_t token_key_id[32] (32 octets)
 * - uint8_t authenticator[Nk] (>= 32 octets)
 */
public final class PrivateAccessToken {
    private final int tokenType;
    private final byte[] nonce;
    private final byte[] challengeDigest;
    private final byte[] tokenKeyId;
    private final byte[] authenticator;
    private final byte[] signedData;

    public PrivateAccessToken(int tokenType, byte[] nonce, byte[] challengeDigest,
                              byte[] tokenKeyId, byte[] authenticator, byte[] signedData) {
        this.tokenType = tokenType;
        this.nonce = nonce != null ? nonce.clone() : new byte[0];
        this.challengeDigest = challengeDigest != null ? challengeDigest.clone() : new byte[0];
        this.tokenKeyId = tokenKeyId != null ? tokenKeyId.clone() : new byte[0];
        this.authenticator = authenticator != null ? authenticator.clone() : new byte[0];
        this.signedData = signedData != null ? signedData.clone() : new byte[0];
    }

    public int getTokenType() {
        return tokenType;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }

    public String getNonceHex() {
        return PatUtils.bytesToHex(nonce);
    }

    public byte[] getChallengeDigest() {
        return challengeDigest.clone();
    }

    public String getChallengeDigestHex() {
        return PatUtils.bytesToHex(challengeDigest);
    }

    public byte[] getTokenKeyId() {
        return tokenKeyId.clone();
    }

    public String getTokenKeyIdHex() {
        return PatUtils.bytesToHex(tokenKeyId);
    }

    public byte[] getAuthenticator() {
        return authenticator.clone();
    }

    public byte[] getSignedData() {
        return signedData.clone();
    }

    @Override
    public String toString() {
        return "PrivateAccessToken{" +
                "tokenType=0x" + Integer.toHexString(tokenType) +
                ", nonce=" + getNonceHex() +
                ", tokenKeyId=" + getTokenKeyIdHex() +
                ", authenticatorLen=" + authenticator.length +
                '}';
    }
}