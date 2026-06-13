// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.crypto.ByteContainer;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;

/**
 * ML-DSA (FIPS 204) private key handle.
 *
 * <p>Stored in <i>seed form</i> only: a single 32-byte &xi; backed by {@link ByteContainer}, so
 * {@link #clearKey()} zeroizes the complete secret and no expanded key ever persists. The
 * expanded BouncyCastle key is reconstructed on demand for each operation
 * ({@link #toBcParams()}).
 *
 * @see MLDSA
 */
public final class MLDSAPrivateKey implements PrivateKey {

    /** Engine-extension key type (not a Java Card {@code KeyBuilder.TYPE_*} constant). */
    public static final byte TYPE_ML_DSA_PRIVATE = (byte) 0x71;

    /** ML-DSA private seed (&xi;) length in bytes. */
    public static final short SEED_LENGTH = 32;

    private final byte paramSet;
    private final ByteContainer seed;

    /**
     * Construct an uninitialized key in persistent memory.
     *
     * @param paramSet one of {@link MLDSA#ML_DSA_44}, {@link MLDSA#ML_DSA_65}, {@link MLDSA#ML_DSA_87}
     */
    public MLDSAPrivateKey(byte paramSet) {
        this(paramSet, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /**
     * Construct an uninitialized key in the requested memory type.
     *
     * @param paramSet   ML-DSA parameter set (see {@link MLDSA})
     * @param memoryType a {@code JCSystem.MEMORY_TYPE_*} constant
     */
    public MLDSAPrivateKey(byte paramSet, byte memoryType) {
        MLDSA.bcParameters(paramSet); // validates paramSet
        this.paramSet = paramSet;
        this.seed = new ByteContainer(memoryType);
    }

    /**
     * @return the ML-DSA parameter set this key was created for
     */
    public byte getParamSet() {
        return paramSet;
    }

    // --- javacard.security.Key -------------------------------------------------------------

    /**
     * @return the parameter set's public-key length in bits (the conventional "key size")
     */
    @Override
    public short getSize() {
        return (short) (MLDSA.publicKeyLength(paramSet) * 8);
    }

    @Override
    public byte getType() {
        return TYPE_ML_DSA_PRIVATE;
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

    /**
     * Reconstruct the expanded BouncyCastle private key from the stored seed.
     *
     * @return live {@link MLDSAPrivateKeyParameters}
     * @throws CryptoException with {@link CryptoException#UNINITIALIZED_KEY} if no seed is set
     */
    MLDSAPrivateKeyParameters toBcParams() {
        if (!seed.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        byte[] xi = new byte[SEED_LENGTH];
        seed.getBytes(xi, (short) 0);
        return new MLDSAPrivateKeyParameters(MLDSA.bcParameters(paramSet), xi);
    }
}
