// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.crypto.ByteContainer;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.PublicKey;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;

/**
 * ML-DSA (FIPS 204) public key handle. Holds the raw encoded public key in a
 * {@link ByteContainer}.
 *
 * @see MLDSA
 */
public final class MLDSAPublicKey implements PublicKey {

    /** Engine-extension key type (not a Java Card {@code KeyBuilder.TYPE_*} constant). */
    public static final byte TYPE_ML_DSA_PUBLIC = (byte) 0x72;

    private final byte paramSet;
    private final ByteContainer encoded;

    /**
     * Construct an uninitialized key in persistent memory.
     *
     * @param paramSet one of {@link MLDSA#ML_DSA_44}, {@link MLDSA#ML_DSA_65}, {@link MLDSA#ML_DSA_87}
     */
    public MLDSAPublicKey(byte paramSet) {
        this(paramSet, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /**
     * Construct an uninitialized key in the requested memory type.
     *
     * @param paramSet   ML-DSA parameter set (see {@link MLDSA})
     * @param memoryType a {@code JCSystem.MEMORY_TYPE_*} constant
     */
    public MLDSAPublicKey(byte paramSet, byte memoryType) {
        MLDSA.bcParameters(paramSet); // validates paramSet
        this.paramSet = paramSet;
        this.encoded = new ByteContainer(memoryType);
    }

    /**
     * @return the ML-DSA parameter set this key was created for
     */
    public byte getParamSet() {
        return paramSet;
    }

    /**
     * Copy the raw encoded public key out.
     *
     * @param buf destination buffer
     * @param off destination offset
     * @return number of bytes written ({@link MLDSA#publicKeyLength(byte)})
     */
    public short getEncoded(byte[] buf, short off) {
        return encoded.getBytes(buf, off);
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
        return TYPE_ML_DSA_PUBLIC;
    }

    @Override
    public void clearKey() {
        encoded.clear();
    }

    @Override
    public boolean isInitialized() {
        return encoded.isInitialized();
    }

    // --- package-private bridge ------------------------------------------------------------

    void setEncoded(byte[] buf, short off, short len) {
        if (len != MLDSA.publicKeyLength(paramSet)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        encoded.setBytes(buf, off, len);
    }

    MLDSAPublicKeyParameters toBcParams() {
        if (!encoded.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        short len = MLDSA.publicKeyLength(paramSet);
        byte[] pk = new byte[len];
        encoded.getBytes(pk, (short) 0);
        return new MLDSAPublicKeyParameters(MLDSA.bcParameters(paramSet), pk);
    }
}
