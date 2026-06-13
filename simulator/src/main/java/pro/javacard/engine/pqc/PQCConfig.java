// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.pqc;

import javacard.security.CryptoException;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Session-wide configuration for the post-quantum (ML-DSA / ML-KEM) extension API.
 *
 * <p>This holder serves two plan items:
 * <ul>
 *   <li><b>Config gate (E1.5)</b> &mdash; {@link #setEnabled(boolean)} switches the whole
 *       extension off so a "strictly Java Card 3.0.5" simulation profile still exists. Every
 *       {@link MLDSA}/{@link MLKEM} operation calls {@link #requireEnabled()} first. Parity
 *       with the applet-side {@code PQC_TEST_MODE} flag.</li>
 *   <li><b>RNG plumbing (E1.3)</b> &mdash; keygen, ML-KEM encapsulation and (hedged) ML-DSA
 *       signing draw from the engine-controlled {@link SecureRandom} returned by
 *       {@link #random()}. {@link #setSeed(byte[])} swaps in a deterministic generator so test
 *       runs are reproducible (parity with the applet's {@code DEBUG_FIXED_RANDOM}).</li>
 * </ul>
 *
 * <p>State is static and process-wide, mirroring how the engine already keeps a single
 * {@link SecureRandom} in {@code RandomDataImpl}. All fields are {@code volatile}; callers that
 * want reproducible output must serialise their own operations (e.g. {@link #setSeed(byte[])}
 * immediately before the operation under test).
 */
public final class PQCConfig {

    private PQCConfig() {
    }

    private static volatile boolean enabled = true;
    private static volatile boolean deterministicSigning = false;
    private static volatile SecureRandom random = new SecureRandom();

    /**
     * Enable or disable the PQC extension for this session (E1.5 gate).
     *
     * @param value {@code true} to allow ML-DSA/ML-KEM operations, {@code false} to forbid them
     */
    public static void setEnabled(boolean value) {
        enabled = value;
    }

    /**
     * @return {@code true} if the PQC extension is currently enabled
     */
    public static boolean isEnabled() {
        return enabled;
    }

    /**
     * Backstop gate used by every extension operation. Throws if the extension is disabled, so a
     * FIPS-approved / strict-3.0.5 profile can prove the PQC paths are unreachable.
     *
     * @throws CryptoException with reason {@link CryptoException#ILLEGAL_USE} when disabled
     */
    static void requireEnabled() {
        if (!enabled) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
    }

    /**
     * @return the engine-controlled {@link SecureRandom} used for keygen, ML-KEM encapsulation
     * and hedged ML-DSA signing
     */
    static SecureRandom random() {
        return random;
    }

    /**
     * Switch to a deterministic generator seeded from the supplied bytes, making keygen and
     * (when {@link #setDeterministicSigning(boolean) deterministic signing} is off) hedged
     * signatures reproducible. Uses {@code SHA1PRNG} in the standard reseed-before-use idiom.
     *
     * @param seed seed material; identical seeds yield identical generator output
     */
    public static void setSeed(byte[] seed) {
        try {
            SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
            prng.setSeed(seed);
            random = prng;
        } catch (NoSuchAlgorithmException e) {
            // SHA1PRNG is mandated on every JRE; treat absence as a configuration error.
            throw new IllegalStateException("SHA1PRNG unavailable", e);
        }
    }

    /**
     * Restore the system {@link SecureRandom} (the default, non-reproducible mode).
     */
    public static void useSystemRandom() {
        random = new SecureRandom();
    }

    /**
     * Select the ML-DSA signing variant. Deterministic signing (FIPS 204 with {@code rnd = 0})
     * makes signatures reproducible without touching {@link #random()}; hedged signing (the
     * default, FIPS 204 recommended) draws per-signature randomness from {@link #random()}.
     *
     * @param value {@code true} for deterministic signing, {@code false} for hedged signing
     */
    public static void setDeterministicSigning(boolean value) {
        deterministicSigning = value;
    }

    /**
     * @return {@code true} if ML-DSA signing is in deterministic mode
     */
    static boolean isDeterministicSigning() {
        return deterministicSigning;
    }
}
