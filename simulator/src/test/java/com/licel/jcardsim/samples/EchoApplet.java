// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.samples;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/**
 * Minimal applet that echoes its command data field back verbatim, for arbitrary content and
 * arbitrary length (multi-KB). Unlike {@link ApduExtendedCasesApplet} it does not constrain the
 * payload to a fixed byte value, so a test can verify byte-exact round-tripping of a varied
 * pattern through the engine's incoming receive loop and outgoing send path.
 *
 * <p>Supported APDU: {@code CLA=0x80 INS=0x10}, Case 4 / 4E. Echoes {@code min(Lc, Ne)} bytes.
 */
public class EchoApplet extends Applet implements ExtendedLength {

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_ECHO = (byte) 0x10;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EchoApplet().register();
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        if (buffer[ISO7816.OFFSET_INS] != INS_ECHO) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        // Reassemble the full incoming data field across as many frames as the engine delivers.
        short readCount = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();
        short offsetCData = apdu.getOffsetCdata();
        byte[] data = JCSystem.makeTransientByteArray(lc, JCSystem.CLEAR_ON_DESELECT);
        short pos = Util.arrayCopyNonAtomic(buffer, offsetCData, data, (short) 0, readCount);
        short bytesLeft = (short) (lc - readCount);
        while (bytesLeft > 0) {
            readCount = apdu.receiveBytes(offsetCData);
            bytesLeft -= readCount;
            pos = Util.arrayCopyNonAtomic(buffer, offsetCData, data, pos, readCount);
        }

        // Echo min(Lc, Ne) bytes back through the outgoing send path.
        short ne = apdu.setOutgoing();
        short outLen = ne < lc ? ne : lc;
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(data, (short) 0, outLen);
    }
}
