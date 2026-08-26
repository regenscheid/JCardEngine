// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.samples.EchoApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Transport smoke test (plan item E2.2) for multi-KB payloads in both directions.
 *
 * <p>An ML-DSA-87 GENERAL AUTHENTICATE round trip moves ~4.7 KB each way (a 4627-byte signature,
 * 2592-byte public key). This pushes payloads of that magnitude and beyond — up to the plan's
 * proposed 8 KB buffer — through the engine's incoming receive loop ({@code setIncomingAndReceive}
 * + {@code receiveBytes}) and outgoing path ({@code sendBytesLong} chunking into the response
 * buffer), verifying byte-exact round-tripping with no frame-count truncation or reordering.
 *
 * <p>Scope note: the simulator's BIBO returns a whole response in one {@code transceive} rather
 * than framing it into T=0 256-byte blocks with client-side GET RESPONSE, so this exercises the
 * engine/tool data path (buffers and send/receive loops), not wire-level T=0 framing. The
 * application-level command-chaining reassembly that OpenFIPS201's PIVAPDU relies on is covered
 * separately by {@code CommandChainingTest} (and end-to-end against the real applet in E2.3).
 */
public class LargePayloadTransportTest {

    private static final int CLA = 0x80;
    private static final int INS_ECHO = 0x10;
    private static final AID AID = AIDUtil.create("0102030405decaf0");

    private static Simulator prepareSimulator() {
        Simulator instance = new Simulator();
        instance.installApplet(AID, EchoApplet.class);
        return instance;
    }

    // Deterministic, non-uniform pattern so a dropped/duplicated/reordered frame is detectable.
    private static byte[] pattern(int len) {
        byte[] data = new byte[len];
        for (int i = 0; i < len; i++) {
            data[i] = (byte) ((i * 31 + 7) & 0xFF);
        }
        return data;
    }

    @ParameterizedTest
    @ValueSource(ints = {2592, 4627, 6000, 8192})
    public void largePayloadRoundTrips(int size) {
        Simulator instance = prepareSimulator();
        byte[] input = pattern(size);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(AID));
            assertEquals(0x9000, sel.getSW());

            ResponseAPDU response = bibo.transmit(new CommandAPDU(CLA, INS_ECHO, 0x00, 0x00, input, size));
            assertEquals(0x9000, response.getSW(), "large echo must succeed at " + size + " bytes");
            assertArrayEquals(input, response.getData(), "echoed payload must round-trip byte-exact at " + size + " bytes");
        }
    }
}
