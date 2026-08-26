// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.CryptoException;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.expectThrows;

/**
 * Functional tests for the ML-KEM extension API (plan items E1.2, E1.3, E1.5).
 */
public class MLKEMTest extends SimulatorCoreTest {

    @AfterMethod
    public void resetConfig() {
        PQCConfig.setEnabled(true);
        PQCConfig.useSystemRandom();
    }

    @DataProvider(name = "paramSets")
    public static Object[][] paramSets() {
        return new Object[][] {
                {MLKEM.ML_KEM_512},
                {MLKEM.ML_KEM_768},
                {MLKEM.ML_KEM_1024},
        };
    }

    private static byte[] seed(int fill) {
        byte[] dz = new byte[MLKEMPrivateKey.SEED_LENGTH];
        for (int i = 0; i < dz.length; i++) {
            dz[i] = (byte) (fill + i);
        }
        return dz;
    }

    @Test(dataProvider = "paramSets")
    public void encapsulateDecapsulateRoundTrip(byte paramSet) {
        MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(paramSet);
        MLKEM.generateKeyPair(pub, priv);

        byte[] ct = new byte[MLKEM.ciphertextLength(paramSet)];
        byte[] ssEncap = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ctLen = MLKEM.encapsulate(pub, ct, (short) 0, ssEncap, (short) 0);
        assertEquals(ctLen, MLKEM.ciphertextLength(paramSet));

        byte[] ssDecap = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ssLen = MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssDecap, (short) 0);
        assertEquals(ssLen, MLKEM.SHARED_SECRET_LENGTH);

        assertEquals(ssDecap, ssEncap, "encapsulated and decapsulated secrets must match");
    }

    @Test(dataProvider = "paramSets")
    public void seedImportIsDeterministic(byte paramSet) {
        byte[] dz = seed(9);

        MLKEMPublicKey pubA = new MLKEMPublicKey(paramSet);
        MLKEM.keyFromSeed(dz, (short) 0, pubA, new MLKEMPrivateKey(paramSet));
        MLKEMPublicKey pubB = new MLKEMPublicKey(paramSet);
        MLKEM.keyFromSeed(dz, (short) 0, pubB, new MLKEMPrivateKey(paramSet));

        byte[] a = new byte[MLKEM.encapsulationKeyLength(paramSet)];
        byte[] b = new byte[MLKEM.encapsulationKeyLength(paramSet)];
        pubA.getEncoded(a, (short) 0);
        pubB.getEncoded(b, (short) 0);
        assertEquals(b, a, "same seed must yield the same encapsulation key");
    }

    @Test
    public void decapsulateWithSeedImportedKey() {
        // Host holds the public key; card holds only the 64-byte seed (the applet's import model).
        byte paramSet = MLKEM.ML_KEM_768;
        byte[] dz = seed(5);
        MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(paramSet);
        MLKEM.keyFromSeed(dz, (short) 0, pub, priv);

        byte[] ct = new byte[MLKEM.ciphertextLength(paramSet)];
        byte[] ssHost = new byte[MLKEM.SHARED_SECRET_LENGTH];
        MLKEM.encapsulate(pub, ct, (short) 0, ssHost, (short) 0);

        byte[] ssCard = new byte[MLKEM.SHARED_SECRET_LENGTH];
        MLKEM.decapsulate(priv, ct, (short) 0, (short) ct.length, ssCard, (short) 0);
        assertEquals(ssCard, ssHost);
    }

    @Test
    public void clearKeyZeroizes() {
        MLKEMPublicKey pub = new MLKEMPublicKey(MLKEM.ML_KEM_512);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(MLKEM.ML_KEM_512);
        MLKEM.generateKeyPair(pub, priv);
        priv.clearKey();
        pub.clearKey();
        assertFalse(priv.isInitialized());
        assertFalse(pub.isInitialized());
    }

    @Test
    public void disabledExtensionThrows() {
        MLKEMPublicKey pub = new MLKEMPublicKey(MLKEM.ML_KEM_512);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(MLKEM.ML_KEM_512);
        PQCConfig.setEnabled(false);
        expectThrows(CryptoException.class, () -> MLKEM.generateKeyPair(pub, priv));
    }

    @Test
    public void invalidParamSetRejected() {
        expectThrows(CryptoException.class, () -> new MLKEMPublicKey((byte) 42));
    }

    /**
     * FIPS 203 implicit rejection: decapsulating a correctly-sized but invalid ciphertext MUST NOT
     * error - the FO transform returns a deterministic pseudorandom secret derived from the private
     * key's implicit-rejection value z. KEM-CAK card-authentication oracle hygiene depends on this:
     * the card must never expose a decapsulation/FO-rejection signal (no exception, no distinct status
     * word, no timing branch) at the card edge. This guards against an engine regression that adds a
     * "ciphertext validity" check (see the applet's ENGINE-API-CONTRACT.md requirement 5).
     */
    @Test(dataProvider = "paramSets")
    public void implicitRejectionOnCorruptedCiphertext(byte paramSet) {
        MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(paramSet);
        MLKEM.generateKeyPair(pub, priv);

        byte[] ct = new byte[MLKEM.ciphertextLength(paramSet)];
        byte[] ssReal = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ctLen = MLKEM.encapsulate(pub, ct, (short) 0, ssReal, (short) 0);

        // Corrupt one byte, preserving the (correct) ciphertext length.
        ct[0] ^= (byte) 0xFF;

        byte[] ssRej = new byte[MLKEM.SHARED_SECRET_LENGTH];
        // Decapsulating an invalid ciphertext must not throw (implicit rejection); an exception fails the test.
        short ssLen = MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssRej, (short) 0);
        assertEquals(ssLen, MLKEM.SHARED_SECRET_LENGTH, "implicit rejection still returns a 32-byte secret");
        assertFalse(Arrays.equals(ssReal, ssRej),
                "implicit-rejection secret must differ from the real shared secret");

        // The rejection secret is deterministic for a given key and ciphertext (derived from z).
        byte[] ssRej2 = new byte[MLKEM.SHARED_SECRET_LENGTH];
        MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssRej2, (short) 0);
        assertEquals(ssRej2, ssRej, "implicit rejection is deterministic for a given key and ciphertext");
    }
}
