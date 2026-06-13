// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import javacard.framework.Util;
import javacard.security.CryptoException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;

/**
 * ML-KEM (FIPS 203) operations for the simulator extension API (plan Route A).
 *
 * <p>Stateless façade over the BouncyCastle lightweight implementation. Decapsulation mirrors the
 * existing ECDH "raw Z out" semantics: ciphertext in, 32-byte shared secret out. Encapsulation is
 * provided for pairwise-consistency self-tests and host-side use.
 *
 * @see MLKEMPrivateKey
 * @see MLKEMPublicKey
 */
public final class MLKEM {

    private MLKEM() {
    }

    // Parameter sets. Engine-local codes (independent of the applet's SP 800-78 PIV algorithm IDs).
    /** ML-KEM-512 (FIPS 203, security category 1). */
    public static final byte ML_KEM_512 = 1;
    /** ML-KEM-768 (FIPS 203, security category 3). */
    public static final byte ML_KEM_768 = 2;
    /** ML-KEM-1024 (FIPS 203, security category 5). */
    public static final byte ML_KEM_1024 = 3;

    /** Shared-secret length in bytes (constant across parameter sets). */
    public static final short SHARED_SECRET_LENGTH = 32;

    // Encoded-length tables, indexed by the parameter set codes above (FIPS 203 / plan §2.1).
    // [unused, 512, 768, 1024]
    private static final short[] ENCAPS_KEY_LENGTH = {0, 800, 1184, 1568};
    private static final short[] CIPHERTEXT_LENGTH = {0, 768, 1088, 1568};

    /**
     * @param paramSet a {@code ML_KEM_*} constant
     * @return encoded encapsulation-key length in bytes
     */
    public static short encapsulationKeyLength(byte paramSet) {
        checkParamSet(paramSet);
        return ENCAPS_KEY_LENGTH[paramSet];
    }

    /**
     * @param paramSet a {@code ML_KEM_*} constant
     * @return ciphertext length in bytes
     */
    public static short ciphertextLength(byte paramSet) {
        checkParamSet(paramSet);
        return CIPHERTEXT_LENGTH[paramSet];
    }

    /**
     * Generate a fresh key pair into the supplied handles. Randomness is drawn from the
     * engine-controlled generator ({@link PQCConfig}); both handles must share the parameter set.
     *
     * @param pub  destination public (encapsulation) key
     * @param priv destination private (decapsulation) key (stored in seed form)
     */
    public static void generateKeyPair(MLKEMPublicKey pub, MLKEMPrivateKey priv) {
        PQCConfig.requireEnabled();
        byte paramSet = requireSameParamSet(pub, priv);
        MLKEMKeyPairGenerator gen = new MLKEMKeyPairGenerator();
        gen.init(new MLKEMKeyGenerationParameters(PQCConfig.random(), bcParameters(paramSet)));
        AsymmetricCipherKeyPair kp = gen.generateKeyPair();
        MLKEMPrivateKeyParameters sk = (MLKEMPrivateKeyParameters) kp.getPrivate();
        byte[] seed = sk.getSeed();
        priv.setSeed(seed, (short) 0, (short) seed.length);
        byte[] ek = sk.getPublicKeyParameters().getEncoded();
        pub.setEncoded(ek, (short) 0, (short) ek.length);
    }

    /**
     * Deterministically derive a key pair from a 64-byte (d&#8214;z) seed, matching the applet's
     * seed-form PUT DATA import and enabling reproducible tests.
     *
     * @param dz   buffer holding the 64-byte seed
     * @param off  offset of the seed in {@code dz}
     * @param pub  destination public key
     * @param priv destination private key
     */
    public static void keyFromSeed(byte[] dz, short off, MLKEMPublicKey pub, MLKEMPrivateKey priv) {
        PQCConfig.requireEnabled();
        requireSameParamSet(pub, priv);
        priv.setSeed(dz, off, MLKEMPrivateKey.SEED_LENGTH);
        byte[] ek = priv.toBcParams().getPublicKeyParameters().getEncoded();
        pub.setEncoded(ek, (short) 0, (short) ek.length);
    }

    /**
     * Decapsulate a ciphertext to recover the 32-byte shared secret (mirrors ECDH "raw Z out").
     *
     * @param key  decapsulation key
     * @param ct   ciphertext buffer
     * @param cOff ciphertext offset
     * @param cLen ciphertext length (must equal {@link #ciphertextLength(byte)})
     * @param ss   destination buffer for the shared secret
     * @param sOff destination offset
     * @return shared-secret length in bytes ({@value #SHARED_SECRET_LENGTH})
     */
    public static short decapsulate(MLKEMPrivateKey key, byte[] ct, short cOff, short cLen,
                                    byte[] ss, short sOff) {
        PQCConfig.requireEnabled();
        if (cLen != ciphertextLength(key.getParamSet())) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        byte[] ciphertext = new byte[cLen];
        Util.arrayCopy(ct, cOff, ciphertext, (short) 0, cLen);
        MLKEMExtractor extractor = new MLKEMExtractor(key.toBcParams());
        byte[] secret = extractor.extractSecret(ciphertext);
        return copyOut(secret, ss, sOff);
    }

    /**
     * Encapsulate against a public key, producing a ciphertext and the shared secret. Used for
     * pairwise-consistency self-tests and host-side flows.
     *
     * @param key  encapsulation key
     * @param ct   destination buffer for the ciphertext
     * @param cOff ciphertext offset
     * @param ss   destination buffer for the shared secret
     * @param sOff shared-secret offset
     * @return ciphertext length in bytes ({@link #ciphertextLength(byte)})
     */
    public static short encapsulate(MLKEMPublicKey key, byte[] ct, short cOff, byte[] ss, short sOff) {
        PQCConfig.requireEnabled();
        MLKEMGenerator generator = new MLKEMGenerator(PQCConfig.random());
        SecretWithEncapsulation enc = generator.generateEncapsulated(key.toBcParams());
        byte[] ciphertext = enc.getEncapsulation();
        byte[] secret = enc.getSecret();
        Util.arrayCopy(ciphertext, (short) 0, ct, cOff, (short) ciphertext.length);
        copyOut(secret, ss, sOff);
        return (short) ciphertext.length;
    }

    // --- internals -------------------------------------------------------------------------

    static MLKEMParameters bcParameters(byte paramSet) {
        switch (paramSet) {
            case ML_KEM_512:
                return MLKEMParameters.ml_kem_512;
            case ML_KEM_768:
                return MLKEMParameters.ml_kem_768;
            case ML_KEM_1024:
                return MLKEMParameters.ml_kem_1024;
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null; // unreachable
        }
    }

    private static void checkParamSet(byte paramSet) {
        bcParameters(paramSet);
    }

    private static byte requireSameParamSet(MLKEMPublicKey pub, MLKEMPrivateKey priv) {
        if (pub.getParamSet() != priv.getParamSet()) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        return pub.getParamSet();
    }

    private static short copyOut(byte[] out, byte[] dest, short off) {
        Util.arrayCopy(out, (short) 0, dest, off, (short) out.length);
        // Defensively wipe the heap copy the BC API handed back.
        Util.arrayFillNonAtomic(out, (short) 0, (short) out.length, (byte) 0);
        return (short) out.length;
    }
}
