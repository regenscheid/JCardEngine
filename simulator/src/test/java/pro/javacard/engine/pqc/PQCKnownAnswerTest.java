// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.licel.jcardsim.SimulatorCoreTest;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Known-answer tests (plan item E1.4) for the ML-DSA / ML-KEM extension API, driven by NIST ACVP
 * vectors (FIPS 203/204) bundled under {@code src/test/resources/pqc/acvp/}.
 *
 * <p>Coverage validates the extension's seed-form construction and signature verification against
 * NIST reference values, independent of the applet:
 * <ul>
 *   <li><b>ML-DSA keyGen</b> — seed (&xi;) &rarr; encoded public key, all three parameter sets.</li>
 *   <li><b>ML-KEM keyGen</b> — seed (d&#8214;z) &rarr; encoded encapsulation key, all three sets.</li>
 *   <li><b>ML-DSA sigVer</b> — NIST signatures (pure mode, empty context, external interface)
 *       verify under the corresponding public key, and a single-bit tamper is rejected.</li>
 * </ul>
 *
 * <p>ML-KEM decapsulation is not KAT'd here: ACVP encap/decap vectors supply the <i>expanded</i>
 * decapsulation key, while this extension's API deliberately accepts only the 64-byte seed (the
 * plan's seed-only key-injection decision, applet plan §7.9). The functional round-trip in
 * {@link MLKEMTest} covers that path instead.
 */
public class PQCKnownAnswerTest extends SimulatorCoreTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final HexFormat HEX = HexFormat.of();

    private static byte mldsaParamSet(String name) {
        switch (name) {
            case "ML-DSA-44": return MLDSA.ML_DSA_44;
            case "ML-DSA-65": return MLDSA.ML_DSA_65;
            case "ML-DSA-87": return MLDSA.ML_DSA_87;
            default: throw new IllegalArgumentException(name);
        }
    }

    private static byte mlkemParamSet(String name) {
        switch (name) {
            case "ML-KEM-512": return MLKEM.ML_KEM_512;
            case "ML-KEM-768": return MLKEM.ML_KEM_768;
            case "ML-KEM-1024": return MLKEM.ML_KEM_1024;
            default: throw new IllegalArgumentException(name);
        }
    }

    private static JsonNode load(String resource) throws IOException {
        try (InputStream in = PQCKnownAnswerTest.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IOException("Missing KAT resource: " + resource);
            }
            return MAPPER.readTree(in);
        }
    }

    @TestFactory
    List<DynamicTest> mldsaKeyGen() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : load("/pqc/acvp/ML-DSA-keyGen.json")) {
            byte paramSet = mldsaParamSet(v.get("paramSet").asText());
            byte[] seed = HEX.parseHex(v.get("seed").asText());
            byte[] expectedPk = HEX.parseHex(v.get("pk").asText());
            tests.add(DynamicTest.dynamicTest("ML-DSA keyGen " + v.get("paramSet").asText() + " tc" + v.get("tcId"), () -> {
                MLDSAPublicKey pub = new MLDSAPublicKey(paramSet);
                MLDSA.keyFromSeed(seed, (short) 0, pub, new MLDSAPrivateKey(paramSet));
                byte[] pk = new byte[MLDSA.publicKeyLength(paramSet)];
                pub.getEncoded(pk, (short) 0);
                assertArrayEquals(expectedPk, pk);
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> mlkemKeyGen() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : load("/pqc/acvp/ML-KEM-keyGen.json")) {
            byte paramSet = mlkemParamSet(v.get("paramSet").asText());
            byte[] seed = HEX.parseHex(v.get("seed").asText());
            byte[] expectedEk = HEX.parseHex(v.get("ek").asText());
            tests.add(DynamicTest.dynamicTest("ML-KEM keyGen " + v.get("paramSet").asText() + " tc" + v.get("tcId"), () -> {
                MLKEMPublicKey pub = new MLKEMPublicKey(paramSet);
                MLKEM.keyFromSeed(seed, (short) 0, pub, new MLKEMPrivateKey(paramSet));
                byte[] ek = new byte[MLKEM.encapsulationKeyLength(paramSet)];
                pub.getEncoded(ek, (short) 0);
                assertArrayEquals(expectedEk, ek);
            }));
        }
        return tests;
    }

    @TestFactory
    List<DynamicTest> mldsaSigVer() throws IOException {
        List<DynamicTest> tests = new ArrayList<>();
        for (JsonNode v : load("/pqc/acvp/ML-DSA-sigVer.json")) {
            byte paramSet = mldsaParamSet(v.get("paramSet").asText());
            byte[] pk = HEX.parseHex(v.get("pk").asText());
            byte[] msg = HEX.parseHex(v.get("message").asText());
            byte[] sig = HEX.parseHex(v.get("signature").asText());
            tests.add(DynamicTest.dynamicTest("ML-DSA sigVer " + v.get("paramSet").asText() + " tc" + v.get("tcId"), () -> {
                MLDSAPublicKey pub = new MLDSAPublicKey(paramSet);
                pub.setEncoded(pk, (short) 0, (short) pk.length);
                assertTrue(MLDSA.verify(pub, msg, (short) 0, (short) msg.length, sig, (short) 0, (short) sig.length),
                        "NIST signature must verify");
                byte[] tampered = msg.clone();
                tampered[0] ^= 0x01;
                assertFalse(MLDSA.verify(pub, tampered, (short) 0, (short) tampered.length, sig, (short) 0, (short) sig.length),
                        "tampered message must not verify");
            }));
        }
        return tests;
    }
}
