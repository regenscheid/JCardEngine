// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

/**
 * Fixed-width key-material slot in the requested Java Card memory type (transient deselect/reset,
 * or persistent). Mirrors the engine's package-private {@code com.licel.jcardsim.crypto.ByteContainer}
 * for the PQC key classes, which live in another package: exact-width set, uninitialized until set,
 * zeroised on clear.
 */
final class KeyBytes {

    private final byte[] data;
    private boolean initialized;

    KeyBytes(byte memoryType, short size) {
        this.data = allocate(memoryType, size);
    }

    private static byte[] allocate(byte memoryType, short size) {
        switch (memoryType) {
            case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
                return JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_DESELECT);
            case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
                return JCSystem.makeTransientByteArray(size, JCSystem.CLEAR_ON_RESET);
            default:
                return Simulator.allocateBytes(size);
        }
    }

    /** Store exactly {@code data.length} bytes; any other length is {@code ILLEGAL_VALUE}. */
    void setBytes(byte[] buff, short offset, short length) {
        if (length != data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(buff, offset, data, (short) 0, length);
        initialized = true;
    }

    /** Copy the stored bytes out; {@code UNINITIALIZED_KEY} if nothing has been stored. */
    short getBytes(byte[] dest, short offset) {
        if (!initialized) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (dest.length - offset < data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(data, (short) 0, dest, offset, (short) data.length);
        return (short) data.length;
    }

    void clear() {
        Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
        initialized = false;
    }

    boolean isInitialized() {
        return initialized;
    }
}
