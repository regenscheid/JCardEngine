// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.crypto.ByteContainer;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.PublicKey;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPublicKeyParameters;

/**
 * ML-KEM (FIPS 203) encapsulation (public) key handle. Holds the raw encoded encapsulation key in
 * a {@link ByteContainer}.
 *
 * @see MLKEM
 */
public final class MLKEMPublicKey implements PublicKey {

    /** Engine-extension key type (not a Java Card {@code KeyBuilder.TYPE_*} constant). */
    public static final byte TYPE_ML_KEM_PUBLIC = (byte) 0x74;

    private final byte paramSet;
    private final ByteContainer encoded;

    /**
     * Construct an uninitialized key in persistent memory.
     *
     * @param paramSet one of {@link MLKEM#ML_KEM_512}, {@link MLKEM#ML_KEM_768}, {@link MLKEM#ML_KEM_1024}
     */
    public MLKEMPublicKey(byte paramSet) {
        this(paramSet, JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /**
     * Construct an uninitialized key in the requested memory type.
     *
     * @param paramSet   ML-KEM parameter set (see {@link MLKEM})
     * @param memoryType a {@code JCSystem.MEMORY_TYPE_*} constant
     */
    public MLKEMPublicKey(byte paramSet, byte memoryType) {
        MLKEM.bcParameters(paramSet); // validates paramSet
        this.paramSet = paramSet;
        this.encoded = new ByteContainer(memoryType);
    }

    /**
     * @return the ML-KEM parameter set this key was created for
     */
    public byte getParamSet() {
        return paramSet;
    }

    /**
     * Copy the raw encoded encapsulation key out.
     *
     * @param buf destination buffer
     * @param off destination offset
     * @return number of bytes written ({@link MLKEM#encapsulationKeyLength(byte)})
     */
    public short getEncoded(byte[] buf, short off) {
        return encoded.getBytes(buf, off);
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
        return TYPE_ML_KEM_PUBLIC;
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
        if (len != MLKEM.encapsulationKeyLength(paramSet)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        encoded.setBytes(buf, off, len);
    }

    MLKEMPublicKeyParameters toBcParams() {
        if (!encoded.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        short len = MLKEM.encapsulationKeyLength(paramSet);
        byte[] ek = new byte[len];
        encoded.getBytes(ek, (short) 0);
        return new MLKEMPublicKeyParameters(MLKEM.bcParameters(paramSet), ek);
    }
}
