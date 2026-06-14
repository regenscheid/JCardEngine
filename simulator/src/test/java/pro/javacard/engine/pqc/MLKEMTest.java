// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.CryptoException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Functional tests for the ML-KEM extension API (plan items E1.2, E1.3, E1.5).
 */
public class MLKEMTest extends SimulatorCoreTest {

    @AfterEach
    void resetConfig() {
        PQCConfig.setEnabled(true);
        PQCConfig.useSystemRandom();
    }

    private static byte[] seed(int fill) {
        byte[] dz = new byte[MLKEMPrivateKey.SEED_LENGTH];
        for (int i = 0; i < dz.length; i++) {
            dz[i] = (byte) (fill + i);
        }
        return dz;
    }

    @ParameterizedTest
    @ValueSource(bytes = {MLKEM.ML_KEM_512, MLKEM.ML_KEM_768, MLKEM.ML_KEM_1024})
    void encapsulateDecapsulateRoundTrip(byte paramSet) {
        MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(paramSet);
        MLKEM.generateKeyPair(pub, priv);

        byte[] ct = new byte[MLKEM.ciphertextLength(paramSet)];
        byte[] ssEncap = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ctLen = MLKEM.encapsulate(pub, ct, (short) 0, ssEncap, (short) 0);
        assertEquals(MLKEM.ciphertextLength(paramSet), ctLen);

        byte[] ssDecap = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ssLen = MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssDecap, (short) 0);
        assertEquals(MLKEM.SHARED_SECRET_LENGTH, ssLen);

        assertArrayEquals(ssEncap, ssDecap, "encapsulated and decapsulated secrets must match");
    }

    @ParameterizedTest
    @ValueSource(bytes = {MLKEM.ML_KEM_512, MLKEM.ML_KEM_768, MLKEM.ML_KEM_1024})
    void seedImportIsDeterministic(byte paramSet) {
        byte[] dz = seed(9);

        MLKEMPublicKey pubA = new MLKEMPublicKey(paramSet);
        MLKEM.keyFromSeed(dz, (short) 0, pubA, new MLKEMPrivateKey(paramSet));
        MLKEMPublicKey pubB = new MLKEMPublicKey(paramSet);
        MLKEM.keyFromSeed(dz, (short) 0, pubB, new MLKEMPrivateKey(paramSet));

        byte[] a = new byte[MLKEM.encapsulationKeyLength(paramSet)];
        byte[] b = new byte[MLKEM.encapsulationKeyLength(paramSet)];
        pubA.getEncoded(a, (short) 0);
        pubB.getEncoded(b, (short) 0);
        assertArrayEquals(a, b, "same seed must yield the same encapsulation key");
    }

    @Test
    void decapsulateWithSeedImportedKey() {
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
        assertArrayEquals(ssHost, ssCard);
    }

    @Test
    void clearKeyZeroizes() {
        MLKEMPublicKey pub = new MLKEMPublicKey(MLKEM.ML_KEM_512);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(MLKEM.ML_KEM_512);
        MLKEM.generateKeyPair(pub, priv);
        priv.clearKey();
        pub.clearKey();
        assertFalse(priv.isInitialized());
        assertFalse(pub.isInitialized());
    }

    @Test
    void disabledExtensionThrows() {
        MLKEMPublicKey pub = new MLKEMPublicKey(MLKEM.ML_KEM_512);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(MLKEM.ML_KEM_512);
        PQCConfig.setEnabled(false);
        assertThrows(CryptoException.class, () -> MLKEM.generateKeyPair(pub, priv));
    }

    @Test
    void invalidParamSetRejected() {
        assertThrows(CryptoException.class, () -> new MLKEMPublicKey((byte) 42));
    }

    /**
     * FIPS 203 implicit rejection: decapsulating a correctly-sized but invalid ciphertext MUST NOT
     * error - the FO transform returns a deterministic pseudorandom secret derived from the private
     * key's implicit-rejection value z. KEM-CAK card-authentication oracle hygiene depends on this:
     * the card must never expose a decapsulation/FO-rejection signal (no exception, no distinct status
     * word, no timing branch) at the card edge. This guards against an engine regression that adds a
     * "ciphertext validity" check (see the applet's ENGINE-API-CONTRACT.md requirement 5).
     */
    @ParameterizedTest
    @ValueSource(bytes = {MLKEM.ML_KEM_512, MLKEM.ML_KEM_768, MLKEM.ML_KEM_1024})
    void implicitRejectionOnCorruptedCiphertext(byte paramSet) {
        MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
        MLKEMPrivateKey priv = new MLKEMPrivateKey(paramSet);
        MLKEM.generateKeyPair(pub, priv);

        byte[] ct = new byte[MLKEM.ciphertextLength(paramSet)];
        byte[] ssReal = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ctLen = MLKEM.encapsulate(pub, ct, (short) 0, ssReal, (short) 0);

        // Corrupt one byte, preserving the (correct) ciphertext length.
        ct[0] ^= (byte) 0xFF;

        byte[] ssRej = new byte[MLKEM.SHARED_SECRET_LENGTH];
        short ssLen = assertDoesNotThrow(
                () -> MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssRej, (short) 0),
                "decapsulating an invalid ciphertext must not throw (implicit rejection)");
        assertEquals(MLKEM.SHARED_SECRET_LENGTH, ssLen, "implicit rejection still returns a 32-byte secret");
        assertFalse(Arrays.equals(ssReal, ssRej),
                "implicit-rejection secret must differ from the real shared secret");

        // The rejection secret is deterministic for a given key and ciphertext (derived from z).
        byte[] ssRej2 = new byte[MLKEM.SHARED_SECRET_LENGTH];
        MLKEM.decapsulate(priv, ct, (short) 0, ctLen, ssRej2, (short) 0);
        assertArrayEquals(ssRej, ssRej2, "implicit rejection is deterministic for a given key and ciphertext");
    }
}
