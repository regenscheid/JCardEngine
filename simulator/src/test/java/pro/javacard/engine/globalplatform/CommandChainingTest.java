// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// Issue #7: a SCP03-wrapped command larger than a short APDU is split by gp-pro into chained
// APDUs (CLA & 0x10). The SD must reassemble the chunks before unwrapping/MAC-checking, otherwise
// the C-MAC (computed over the full command) fails on the first chunk and process_mac throws 6985.
public class CommandChainingTest {

    // An INS the SecurityDomainApplet does not handle: a successful unwrap reaches the dispatch
    // default and returns 6D00 (INS_NOT_SUPPORTED). A failed C-MAC instead returns 6985 from
    // process_mac. This isolates "did the chained command unwrap+MAC-validate" from any handler.
    private static final int UNKNOWN_INS = 0xEE;

    @Test
    void chainedCommandReassembledAndMacValidated_macMode() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            GPSession gp = openIsd(bibo, EnumSet.of(GPSession.APDUMode.MAC));
            // 300-byte data field: MAC-wrapped form exceeds 255, so gp-pro chains it.
            var resp = gp.transmit(new CommandAPDU(0x80, UNKNOWN_INS, 0x00, 0x00, new byte[300]));
            System.out.println(">>> MAC-mode chained SW = " + String.format("%04X", resp.getSW()));
            assertNotEquals(0x6985, resp.getSW(), "C-MAC must validate over the reassembled chained command");
            assertEquals(0x6D00, resp.getSW(), "unwrap should succeed and reach the unknown-INS dispatch default");
        }
    }

    @Test
    void chainedCommandReassembledAndMacValidated_encMode() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        try (var bibo = sim.connect()) {
            GPSession gp = openIsd(bibo, EnumSet.of(GPSession.APDUMode.MAC, GPSession.APDUMode.ENC));
            var resp = gp.transmit(new CommandAPDU(0x80, UNKNOWN_INS, 0x00, 0x00, new byte[300]));
            System.out.println(">>> ENC-mode chained SW = " + String.format("%04X", resp.getSW()));
            assertNotEquals(0x6985, resp.getSW(), "C-MAC must validate over the reassembled chained command (ENC)");
            assertEquals(0x6D00, resp.getSW(), "unwrap should succeed and reach the unknown-INS dispatch default (ENC)");
        }
    }
}
