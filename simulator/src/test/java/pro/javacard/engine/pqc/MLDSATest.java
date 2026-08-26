// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.CryptoException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Functional tests for the ML-DSA extension API (plan items E1.2, E1.3, E1.5).
 */
public class MLDSATest extends SimulatorCoreTest {

    @AfterMethod
    public void resetConfig() {
        PQCConfig.setEnabled(true);
        PQCConfig.setDeterministicSigning(false);
        PQCConfig.useSystemRandom();
    }

    @DataProvider(name = "paramSets")
    public static Object[][] paramSets() {
        return new Object[][] {
                { MLDSA.ML_DSA_44 },
                { MLDSA.ML_DSA_65 },
                { MLDSA.ML_DSA_87 },
        };
    }

    private static byte[] seed(int fill) {
        byte[] xi = new byte[MLDSAPrivateKey.SEED_LENGTH];
        for (int i = 0; i < xi.length; i++) {
            xi[i] = (byte) (fill + i);
        }
        return xi;
    }

    @Test(dataProvider = "paramSets")
    public void generateSignVerifyRoundTrip(byte paramSet) {
        MLDSAPublicKey pub = new MLDSAPublicKey(paramSet);
        MLDSAPrivateKey priv = new MLDSAPrivateKey(paramSet);
        MLDSA.generateKeyPair(pub, priv);

        assertTrue(pub.isInitialized());
        assertTrue(priv.isInitialized());

        byte[] msg = "PIV GENERAL AUTHENTICATE challenge".getBytes();
        byte[] sig = new byte[MLDSA.signatureLength(paramSet)];
        short n = MLDSA.sign(priv, msg, (short) 0, (short) msg.length, sig, (short) 0);

        assertEquals(n, MLDSA.signatureLength(paramSet));
        assertTrue(MLDSA.verify(pub, msg, (short) 0, (short) msg.length, sig, (short) 0, n));

        // A tampered message must not verify.
        msg[0] ^= 0x01;
        assertFalse(MLDSA.verify(pub, msg, (short) 0, (short) msg.length, sig, (short) 0, n));
    }

    @Test(dataProvider = "paramSets")
    public void seedImportIsDeterministic(byte paramSet) {
        byte[] xi = seed(7);

        MLDSAPublicKey pubA = new MLDSAPublicKey(paramSet);
        MLDSAPrivateKey privA = new MLDSAPrivateKey(paramSet);
        MLDSA.keyFromSeed(xi, (short) 0, pubA, privA);

        MLDSAPublicKey pubB = new MLDSAPublicKey(paramSet);
        MLDSAPrivateKey privB = new MLDSAPrivateKey(paramSet);
        MLDSA.keyFromSeed(xi, (short) 0, pubB, privB);

        byte[] a = new byte[MLDSA.publicKeyLength(paramSet)];
        byte[] b = new byte[MLDSA.publicKeyLength(paramSet)];
        pubA.getEncoded(a, (short) 0);
        pubB.getEncoded(b, (short) 0);
        assertEquals(a, b, "same seed must yield the same public key");
    }

    @Test
    public void seededKeygenIsReproducible() {
        byte paramSet = MLDSA.ML_DSA_65;
        byte[] rngSeed = "deterministic-keygen".getBytes();

        PQCConfig.setSeed(rngSeed);
        MLDSAPublicKey pubA = new MLDSAPublicKey(paramSet);
        MLDSA.generateKeyPair(pubA, new MLDSAPrivateKey(paramSet));

        PQCConfig.setSeed(rngSeed);
        MLDSAPublicKey pubB = new MLDSAPublicKey(paramSet);
        MLDSA.generateKeyPair(pubB, new MLDSAPrivateKey(paramSet));

        byte[] a = new byte[MLDSA.publicKeyLength(paramSet)];
        byte[] b = new byte[MLDSA.publicKeyLength(paramSet)];
        pubA.getEncoded(a, (short) 0);
        pubB.getEncoded(b, (short) 0);
        assertEquals(a, b, "same RNG seed must yield the same generated key");
    }

    @Test
    public void deterministicSigningIsReproducibleHedgedIsNot() {
        byte paramSet = MLDSA.ML_DSA_65;
        MLDSAPublicKey pub = new MLDSAPublicKey(paramSet);
        MLDSAPrivateKey priv = new MLDSAPrivateKey(paramSet);
        MLDSA.keyFromSeed(seed(1), (short) 0, pub, priv);

        byte[] msg = "msg".getBytes();
        int len = MLDSA.signatureLength(paramSet);

        PQCConfig.setDeterministicSigning(true);
        byte[] d1 = new byte[len];
        byte[] d2 = new byte[len];
        MLDSA.sign(priv, msg, (short) 0, (short) msg.length, d1, (short) 0);
        MLDSA.sign(priv, msg, (short) 0, (short) msg.length, d2, (short) 0);
        assertEquals(d1, d2, "deterministic signing must be reproducible");

        PQCConfig.setDeterministicSigning(false);
        byte[] h1 = new byte[len];
        byte[] h2 = new byte[len];
        MLDSA.sign(priv, msg, (short) 0, (short) msg.length, h1, (short) 0);
        MLDSA.sign(priv, msg, (short) 0, (short) msg.length, h2, (short) 0);
        assertFalse(java.util.Arrays.equals(h1, h2), "hedged signing must vary");

        // Both conventions still verify.
        assertTrue(MLDSA.verify(pub, msg, (short) 0, (short) msg.length, d1, (short) 0, (short) len));
        assertTrue(MLDSA.verify(pub, msg, (short) 0, (short) msg.length, h1, (short) 0, (short) len));
    }

    @Test
    public void externalMuRoundTrip() {
        byte paramSet = MLDSA.ML_DSA_87;
        MLDSAPublicKey pub = new MLDSAPublicKey(paramSet);
        MLDSAPrivateKey priv = new MLDSAPrivateKey(paramSet);
        MLDSA.keyFromSeed(seed(3), (short) 0, pub, priv);

        byte[] mu = new byte[64];
        for (int i = 0; i < 64; i++) {
            mu[i] = (byte) (0xA0 + i);
        }
        byte[] sig = new byte[MLDSA.signatureLength(paramSet)];
        short n = MLDSA.signExternalMu(priv, mu, (short) 0, sig, (short) 0);
        assertTrue(MLDSA.verifyExternalMu(pub, mu, (short) 0, sig, (short) 0, n));
    }

    @Test
    public void clearKeyZeroizes() {
        MLDSAPublicKey pub = new MLDSAPublicKey(MLDSA.ML_DSA_44);
        MLDSAPrivateKey priv = new MLDSAPrivateKey(MLDSA.ML_DSA_44);
        MLDSA.generateKeyPair(pub, priv);
        assertTrue(priv.isInitialized());
        priv.clearKey();
        pub.clearKey();
        assertFalse(priv.isInitialized());
        assertFalse(pub.isInitialized());
    }

    @Test
    public void disabledExtensionThrows() {
        MLDSAPublicKey pub = new MLDSAPublicKey(MLDSA.ML_DSA_44);
        MLDSAPrivateKey priv = new MLDSAPrivateKey(MLDSA.ML_DSA_44);
        PQCConfig.setEnabled(false);
        expectThrows(CryptoException.class, () -> MLDSA.generateKeyPair(pub, priv));
    }

    @Test
    public void invalidParamSetRejected() {
        expectThrows(CryptoException.class, () -> new MLDSAPrivateKey((byte) 99));
    }
}
