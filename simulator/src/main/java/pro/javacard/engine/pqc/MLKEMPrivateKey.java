// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.crypto.ByteContainer;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;

/**
 * ML-KEM (FIPS 203) decapsulation (private) key handle.
 *
 * <p>Stored in <i>seed form</i> only: the 64-byte (d&#8214;z) seed backed by {@link ByteContainer},
 * so {@link #clearKey()} zeroizes the complete secret and no expanded key persists. The expanded
 * BouncyCastle key is reconstructed on demand ({@link #toBcParams()}).
 *
 * @see MLKEM
 */
public final class MLKEMPrivateKey implements PrivateKey {

    /** Engine-extension key type (not a Java Card {@code KeyBuilder.TYPE_*} constant). */
    public static final byte TYPE_ML_KEM_PRIVATE = (byte) 0x73;

    /** ML-KEM private seed (d&#8214;z) length in bytes. */
    public static final short SEED_LENGTH = 64;

    private final byte paramSet;
    private final ByteContainer seed;

    /**
     * Construct an uninitialized key in persistent memory.
     *
     * @param paramSet one of {@link MLKEM#ML_KEM_512}, {@link MLKEM#ML_KEM_768}, {@link MLKEM#ML_KEM_1024}
     */
    public MLKEMPrivateKey(byte paramSet) {
        this(paramSet, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /**
     * Construct an uninitialized key in the requested memory type.
     *
     * @param paramSet   ML-KEM parameter set (see {@link MLKEM})
     * @param memoryType a {@code JCSystem.MEMORY_TYPE_*} constant
     */
    public MLKEMPrivateKey(byte paramSet, byte memoryType) {
        MLKEM.bcParameters(paramSet); // validates paramSet
        this.paramSet = paramSet;
        this.seed = new ByteContainer(memoryType);
    }

    /**
     * @return the ML-KEM parameter set this key was created for
     */
    public byte getParamSet() {
        return paramSet;
    }

    // --- javacard.security.Key -------------------------------------------------------------

    /**
     * @return the parameter set's encapsulation-key length in bits (the conventional "key size")
     */
    @Override
    public short getSize() {
        return (short) (MLKEM.encapsulationKeyLength(paramSet) * 8);
    }

    @Override
    public byte getType() {
        return TYPE_ML_KEM_PRIVATE;
    }

    @Override
    public void clearKey() {
        seed.clear();
    }

    @Override
    public boolean isInitialized() {
        return seed.isInitialized();
    }

    // --- package-private bridge ------------------------------------------------------------

    void setSeed(byte[] buf, short off, short len) {
        if (len != SEED_LENGTH) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        seed.setBytes(buf, off, len);
    }

    MLKEMPrivateKeyParameters toBcParams() {
        if (!seed.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        byte[] dz = new byte[SEED_LENGTH];
        seed.getBytes(dz, (short) 0);
        return new MLKEMPrivateKeyParameters(MLKEM.bcParameters(paramSet), dz);
    }
}
