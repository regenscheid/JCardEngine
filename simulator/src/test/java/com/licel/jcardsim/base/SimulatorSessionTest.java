// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.HelloWorldApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.api.Test;
import pro.javacard.engine.JavaCardEngine;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

// Opportunistic locking: an idle session hands the card lock back (so another reader can take the
// card) but stays open - the next command re-acquires the lock instead of throwing
// "Session already closed". This is what lets a long-lived vsmartcard adapter survive idle gaps.
public class SimulatorSessionTest {

    private static final AID APP = AIDUtil.create("0102030405");
    private static final byte[] SELECT = {0x00, (byte) 0xA4, 0x04, 0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x00};

    private static short sw(byte[] r) {
        return (short) (((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF));
    }

    @Test
    void commandAfterIdleReleaseReacquiresInsteadOfFailing() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.installApplet(APP, HelloWorldApplet.class);

        // Short idle timeout: the watchdog releases the lock between commands.
        try (var bibo = sim.connectFor(Duration.ofMillis(40), "T=1", false)) {
            assertEquals((short) 0x9000, sw(bibo.transceive(SELECT)), "first SELECT");

            // Stay idle well past the timeout: the lock is handed back, the session stays open.
            Thread.sleep(250);

            // Pre-fix this threw IllegalStateException("Session already closed"); now it re-acquires.
            assertEquals((short) 0x9000, sw(bibo.transceive(SELECT)), "SELECT after idle lock-release");
        }
    }

    @Test
    void idleReleaseLetsASecondSessionTakeTheCard() throws Exception {
        var sim = new JavaCardEngine.Builder().build();
        sim.installApplet(APP, HelloWorldApplet.class);

        // First session holds the lock, then goes idle and releases it.
        var first = sim.connectFor(Duration.ofMillis(40), "T=1", false);
        assertEquals((short) 0x9000, sw(first.transceive(SELECT)), "first session SELECT");
        Thread.sleep(250); // first session now idle -> lock released, but still open

        // A second session (e.g. the contactless reader) can now take the card without the first
        // being closed. With idleTimeout 0 it would hold the lock until close and this would block.
        try (var second = sim.connectFor(Duration.ZERO, "T=CL", false)) {
            assertEquals((short) 0x9000, sw(second.transceive(SELECT)), "second session SELECT");
        }
        // And the first session is still usable - it re-acquires on its next command.
        assertEquals((short) 0x9000, sw(first.transceive(SELECT)), "first session still usable after the second");
        first.close();
        assertTrue(true);
    }
}
