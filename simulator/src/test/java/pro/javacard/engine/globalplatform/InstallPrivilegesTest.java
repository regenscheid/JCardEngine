// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.globalplatform;

import javacard.framework.AID;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;
import com.licel.jcardsim.samples.HelloWorldApplet;
import pro.javacard.gp.GPRegistryEntry.Privilege;
import pro.javacard.gp.data.BitField;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static pro.javacard.engine.globalplatform.GPTestUtils.gpAID;
import static pro.javacard.engine.globalplatform.GPTestUtils.openIsd;

// Installing an applet with a GP privilege bitfield (as JCardTool's --privileges does) must actually
// grant the privilege, so EngineRegistryEntry.isPrivileged() returns true for it. This is what gates
// Global PIN (CVM) management - e.g. PUK unblock via CVM.resetAndUnblockState() in EngineGlobalPIN.
public class InstallPrivilegesTest {

    private static final AID APP = GPTestUtils.test_aid("9E9E");

    @Test
    void installWithCvmManagementGrantsIt() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.installApplet(APP, HelloWorldApplet.class,
                BitField.toBytes(EnumSet.of(Privilege.CVMManagement)), new byte[0]);
        try (var bibo = sim.connect()) {
            var entry = openIsd(bibo).getRegistry().allApplets().stream()
                    .filter(e -> e.getAID().equals(gpAID(APP))).findFirst().orElseThrow();
            assertTrue(entry.getPrivileges().contains(Privilege.CVMManagement),
                    "applet installed with CVMManagement should report the privilege");
        }
    }

    @Test
    void installWithoutPrivilegesGrantsNone() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.installApplet(APP, HelloWorldApplet.class, new byte[0]);
        try (var bibo = sim.connect()) {
            var entry = openIsd(bibo).getRegistry().allApplets().stream()
                    .filter(e -> e.getAID().equals(gpAID(APP))).findFirst().orElseThrow();
            assertFalse(entry.getPrivileges().contains(Privilege.CVMManagement),
                    "applet installed without privileges should hold none");
        }
    }
}
