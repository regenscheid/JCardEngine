// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import javacard.framework.Util;
import javacard.security.CryptoException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;

/**
 * ML-DSA (FIPS 204) operations for the simulator extension API (plan Route A).
 *
 * <p>Stateless façade over the BouncyCastle lightweight implementation. The signing convention is
 * <b>pure ML-DSA with an empty context string</b> (the plan's test choice, applet plan §7.3); the
 * convention is isolated here so it can change without touching key classes or the applet. An
 * {@link #signExternalMu ExternalMu} entry point is provided as a switchable alternative.
 *
 * @see MLDSAPrivateKey
 * @see MLDSAPublicKey
 */
public final class MLDSA {

    private MLDSA() {
    }

    // Parameter sets. Engine-local codes (independent of the applet's SP 800-78 PIV algorithm IDs;
    // the applet maps its IDs onto these).
    /** ML-DSA-44 (FIPS 204, security category 2). */
    public static final byte ML_DSA_44 = 1;
    /** ML-DSA-65 (FIPS 204, security category 3). */
    public static final byte ML_DSA_65 = 2;
    /** ML-DSA-87 (FIPS 204, security category 5). */
    public static final byte ML_DSA_87 = 3;

    // Encoded-length tables, indexed by the parameter set codes above (FIPS 204 / plan §2.1).
    // [unused, 44, 65, 87]
    private static final short[] PUBLIC_KEY_LENGTH = {0, 1312, 1952, 2592};
    private static final short[] SIGNATURE_LENGTH = {0, 2420, 3309, 4627};

    /**
     * @param paramSet a {@code ML_DSA_*} constant
     * @return encoded public-key length in bytes for the parameter set
     */
    public static short publicKeyLength(byte paramSet) {
        checkParamSet(paramSet);
        return PUBLIC_KEY_LENGTH[paramSet];
    }

    /**
     * @param paramSet a {@code ML_DSA_*} constant
     * @return signature length in bytes for the parameter set
     */
    public static short signatureLength(byte paramSet) {
        checkParamSet(paramSet);
        return SIGNATURE_LENGTH[paramSet];
    }

    /**
     * Generate a fresh key pair into the supplied handles. Randomness is drawn from the
     * engine-controlled generator ({@link PQCConfig}); both handles must share the parameter set.
     *
     * @param pub  destination public key
     * @param priv destination private key (stored in seed form)
     */
    public static void generateKeyPair(MLDSAPublicKey pub, MLDSAPrivateKey priv) {
        PQCConfig.requireEnabled();
        byte paramSet = requireSameParamSet(pub, priv);
        MLDSAKeyPairGenerator gen = new MLDSAKeyPairGenerator();
        gen.init(new MLDSAKeyGenerationParameters(PQCConfig.random(), bcParameters(paramSet)));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        MLDSAPrivateKeyParameters sk = (MLDSAPrivateKeyParameters) kp.getPrivate();
        byte[] seed = sk.getSeed();
        priv.setSeed(seed, (short) 0, (short) seed.length);
        byte[] pk = sk.getPublicKeyParameters().getEncoded();
        pub.setEncoded(pk, (short) 0, (short) pk.length);
    }

    /**
     * Deterministically derive a key pair from a 32-byte seed (&xi;), matching the applet's
     * seed-form PUT DATA import and enabling reproducible tests.
     *
     * @param xi   buffer holding the 32-byte seed
     * @param off  offset of the seed in {@code xi}
     * @param pub  destination public key
     * @param priv destination private key
     */
    public static void keyFromSeed(byte[] xi, short off, MLDSAPublicKey pub, MLDSAPrivateKey priv) {
        PQCConfig.requireEnabled();
        requireSameParamSet(pub, priv);
        priv.setSeed(xi, off, MLDSAPrivateKey.SEED_LENGTH);
        byte[] pk = priv.toBcParams().getPublicKeyParameters().getEncoded();
        pub.setEncoded(pk, (short) 0, (short) pk.length);
    }

    /**
     * Sign a message with pure ML-DSA and an empty context string.
     *
     * <p>Hedged or deterministic per {@link PQCConfig#setDeterministicSigning(boolean)}.
     *
     * @param key  signing key
     * @param msg  message buffer
     * @param mOff message offset
     * @param mLen message length
     * @param sig  destination buffer for the signature
     * @param sOff destination offset
     * @return signature length in bytes
     */
    public static short sign(MLDSAPrivateKey key, byte[] msg, short mOff, short mLen, byte[] sig, short sOff) {
        PQCConfig.requireEnabled();
        MLDSASigner signer = new MLDSASigner();
        MLDSAPrivateKeyParameters sk = key.toBcParams();
        CipherParameters params = PQCConfig.isDeterministicSigning()
                ? sk
                : new ParametersWithRandom(sk, PQCConfig.random());
        signer.init(true, params);
        signer.update(msg, mOff, mLen);
        byte[] out = generate(signer);
        return copyOut(out, sig, sOff);
    }

    /**
     * Verify a pure ML-DSA signature (empty context). Host/test side.
     *
     * @param key  verification key
     * @param msg  message buffer
     * @param mOff message offset
     * @param mLen message length
     * @param sig  signature buffer
     * @param sOff signature offset
     * @param sLen signature length
     * @return {@code true} if the signature is valid
     */
    public static boolean verify(MLDSAPublicKey key, byte[] msg, short mOff, short mLen,
                                 byte[] sig, short sOff, short sLen) {
        PQCConfig.requireEnabled();
        MLDSASigner signer = new MLDSASigner();
        signer.init(false, key.toBcParams());
        signer.update(msg, mOff, mLen);
        byte[] s = new byte[sLen];
        Util.arrayCopy(sig, sOff, s, (short) 0, sLen);
        return signer.verifySignature(s);
    }

    /**
     * ExternalMu variant: sign a pre-computed 64-byte &mu; (FIPS 204 §6.2). Kept as a switchable
     * alternative to {@link #sign} so the applet's signing-input convention (applet plan §7.3) can
     * change without engine changes. Keeps APDUs small for arbitrarily large messages.
     *
     * @param key  signing key
     * @param mu   buffer holding the 64-byte &mu;
     * @param muOff offset of &mu; in the buffer
     * @param sig  destination buffer
     * @param sOff destination offset
     * @return signature length in bytes
     */
    public static short signExternalMu(MLDSAPrivateKey key, byte[] mu, short muOff, byte[] sig, short sOff) {
        PQCConfig.requireEnabled();
        MLDSASigner signer = new MLDSASigner();
        MLDSAPrivateKeyParameters sk = key.toBcParams();
        CipherParameters params = PQCConfig.isDeterministicSigning()
                ? sk
                : new ParametersWithRandom(sk, PQCConfig.random());
        signer.init(true, params);
        byte[] muBytes = new byte[64];
        Util.arrayCopy(mu, muOff, muBytes, (short) 0, (short) 64);
        byte[] out = generateMu(signer, muBytes);
        return copyOut(out, sig, sOff);
    }

    /**
     * Verify an ExternalMu signature against a pre-computed 64-byte &mu;. Host/test side.
     *
     * @param key   verification key
     * @param mu    buffer holding the 64-byte &mu;
     * @param muOff offset of &mu;
     * @param sig   signature buffer
     * @param sOff  signature offset
     * @param sLen  signature length
     * @return {@code true} if the signature is valid
     */
    public static boolean verifyExternalMu(MLDSAPublicKey key, byte[] mu, short muOff,
                                           byte[] sig, short sOff, short sLen) {
        PQCConfig.requireEnabled();
        MLDSASigner signer = new MLDSASigner();
        signer.init(false, key.toBcParams());
        byte[] muBytes = new byte[64];
        Util.arrayCopy(mu, muOff, muBytes, (short) 0, (short) 64);
        byte[] s = new byte[sLen];
        Util.arrayCopy(sig, sOff, s, (short) 0, sLen);
        return verifyMu(signer, muBytes, s);
    }

    // --- internals -------------------------------------------------------------------------

    static MLDSAParameters bcParameters(byte paramSet) {
        switch (paramSet) {
            case ML_DSA_44:
                return MLDSAParameters.ml_dsa_44;
            case ML_DSA_65:
                return MLDSAParameters.ml_dsa_65;
            case ML_DSA_87:
                return MLDSAParameters.ml_dsa_87;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null; // unreachable
        }
    }

    private static void checkParamSet(byte paramSet) {
        bcParameters(paramSet);
    }

    private static byte requireSameParamSet(MLDSAPublicKey pub, MLDSAPrivateKey priv) {
        if (pub.getParamSet() != priv.getParamSet()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return pub.getParamSet();
    }

    private static byte[] generate(MLDSASigner signer) {
        try {
            return signer.generateSignature();
        } catch (org.bouncycastle.crypto.CryptoException e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            return null; // unreachable
        }
    }

    private static byte[] generateMu(MLDSASigner signer, byte[] mu) {
        try {
            return signer.generateMuSignature(mu);
        } catch (org.bouncycastle.crypto.CryptoException e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
            return null; // unreachable
        }
    }

    private static boolean verifyMu(MLDSASigner signer, byte[] mu, byte[] sig) {
        return signer.verifyMuSignature(mu, sig);
    }

    private static short copyOut(byte[] out, byte[] dest, short off) {
        Util.arrayCopy(out, (short) 0, dest, off, (short) out.length);
        // Defensively wipe the heap copy the BC API handed back.
        Util.arrayFillNonAtomic(out, (short) 0, (short) out.length, (byte) 0);
        return (short) out.length;
    }
}
