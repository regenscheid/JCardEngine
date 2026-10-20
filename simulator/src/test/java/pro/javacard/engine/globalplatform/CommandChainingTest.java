// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import apdu4j.core.CommandAPDU;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;
import pro.javacard.tlv.TLV;
import pro.javacard.gp.GPSession;

import java.util.EnumSet;

import static org.testng.Assert.assertEquals;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

public class CommandChainingTest {
    @DataProvider(name = "commands")
    public static Object[][] commands() {
        return new Object[][] {{300, false}, {300, true}, {6000, false}, {6000, true}};
    }

    @Test(dataProvider = "commands")
    public void reassembledCommandPassesMacAndReachesHandler(int size, boolean encrypted) throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        var mode = EnumSet.of(GPSession.APDUMode.MAC);
        if (encrypted) {
            mode.add(GPSession.APDUMode.ENC);
        }
        try (var bibo = sim.connect()) {
            var gp = openIsd(bibo, mode);
            // GP chains DELETE using P1.b8. A valid TLV without the required 4F AID reaches
            // the DELETE handler and returns 6A80 after the complete command's MAC is checked
            // and its body decrypted. A broken chain fails before this, usually with 6985.
            // 6000 bytes crosses more than twenty short-APDU frames.
            byte[] payload = TLV.of(0xC1, new byte[size]).encode();
            var response = gp.transmit(new CommandAPDU(0x80, 0xE4, 0, 0, payload));
            assertEquals(response.getSW(), 0x6A80, "Authenticated command must reach DELETE validation");
        }
    }
}
