// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation <code>Cipher</code> with symmetric keys based
 * on BouncyCastle CryptoAPI.
 *
 * <h3>Padding handling</h3>
 * <p>
 * JavaCard's {@link Cipher#update(byte[], short, short, byte[], short)} contract
 * requires that all complete blocks are output immediately. BouncyCastle's
 * {@code PaddedBufferedBlockCipher}, however, withholds the last block during
 * encryption because it cannot know whether {@code doFinal()} will be called next
 * (and padding needs to be appended). This causes {@code update()} to return fewer
 * bytes than expected, breaking applets that rely on the JavaCard contract — notably
 * PIV Secure Messaging response wrapping for large objects.
 * </p>
 * <p>
 * To match real JavaCard behaviour, padded algorithms use an <em>unpadded</em>
 * {@link BufferedBlockCipher} for block processing (so {@code update()} flushes all
 * complete blocks), and padding is applied/removed manually in {@code doFinal()}
 * using BouncyCastle's {@link BlockCipherPadding} classes.
 * </p>
 *
 * @see Cipher
 */
@SuppressWarnings("deprecation") // bc ..
public class SymmetricCipherImpl extends Cipher {

    private static final Logger log = LoggerFactory.getLogger(SymmetricCipherImpl.class);
    byte algorithm;
    BufferedBlockCipher engine;
    boolean isInitialized;
    boolean isEncrypting;

    /**
     * The padding strategy for this cipher, or {@code null} for unpadded algorithms.
     * When set, the engine is always an unpadded {@link BufferedBlockCipher} and
     * padding is handled manually in {@link #doFinal}.
     */
    BlockCipherPadding padding;

    public SymmetricCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        selectCipherEngine(theKey);
        isEncrypting = (theMode == MODE_ENCRYPT);
        engine.init(isEncrypting, ((SymmetricKeyImpl) theKey).getParameters());
        isInitialized = true;
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        switch (algorithm) {
            case ALG_DES_ECB_NOPAD:
            case ALG_DES_ECB_ISO9797_M1:
            case ALG_DES_ECB_ISO9797_M2:
            case ALG_DES_ECB_PKCS5:
            case ALG_KOREAN_SEED_ECB_NOPAD:
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                break;
            case ALG_DES_CBC_NOPAD:
            case ALG_DES_CBC_ISO9797_M1:
            case ALG_DES_CBC_ISO9797_M2:
            case ALG_DES_CBC_PKCS5:
                if (bLen != (short) 8) {
                    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
                }
                break;
            default:
                log.trace("No init for cipher algo: " + algorithm);
        }
        selectCipherEngine(theKey);
        isEncrypting = (theMode == MODE_ENCRYPT);
        byte[] iv = JCSystem.makeTransientByteArray(bLen, JCSystem.CLEAR_ON_RESET);
        Util.arrayCopyNonAtomic(bArray, bOff, iv, (short) 0, bLen);
        engine.init(isEncrypting, new ParametersWithIV(((SymmetricKeyImpl) theKey).getParameters(), iv));
        isInitialized = true;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    /**
     * Completes a cipher operation, applying or removing padding if this is a padded algorithm.
     *
     * <p>For <strong>padded encrypt</strong>: the plaintext from {@code inBuff} is processed through
     * the unpadded engine, then ISO/PKCS padding is appended and the final block is encrypted.
     *
     * <p>For <strong>padded decrypt</strong>: all ciphertext is decrypted through the unpadded engine,
     * then the padding bytes are identified and stripped from the output.
     *
     * <p>For <strong>unpadded</strong> algorithms: delegates directly to the engine's
     * {@code processBytes()} + {@code doFinal()}.
     */
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }

        if (log.isDebugEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("doFinal(alg=").append(algorithm & 0xFF);
            sb.append(padding != null ? " padded" : " nopad");
            sb.append(") inLen=").append(inLength).append(" in=");
            for (int i = inOffset; i < inOffset + inLength; i++) sb.append(String.format("%02X", inBuff[i]));
            log.debug(sb.toString());
        }

        try {
            short total;

            if (padding != null && isEncrypting) {
                // PADDED ENCRYPT: process all input through the unpadded engine, then construct
                // a padding block and feed it as additional input so the engine encrypts it.
                //
                // The unpadded engine outputs all complete blocks immediately. If inLength is
                // not block-aligned, the engine buffers the trailing partial block internally.
                // We then feed padding bytes that complete that block, causing the engine to
                // flush it. If inLength IS block-aligned, we feed a full block of padding.
                total = (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);

                int blockSize = engine.getBlockSize();
                int lastBlockBytes = inLength % blockSize;

                // Build the padding: a new block filled from the padding-start position.
                // addPadding(block, offset) writes 0x80 at offset, then 0x00 to end of block.
                byte[] padBytes = new byte[blockSize];
                padding.addPadding(padBytes, lastBlockBytes);

                // Feed only the padding portion (the bytes after the partial-block position)
                // as additional plaintext. The engine combines them with any buffered partial
                // block to produce one final encrypted block.
                int padLen = blockSize - lastBlockBytes;
                total += (short) engine.processBytes(padBytes, lastBlockBytes, padLen, outBuff, outOffset + total);
                total += (short) engine.doFinal(outBuff, outOffset + total);

            } else if (padding != null && !isEncrypting) {
                // PADDED DECRYPT: decrypt all complete blocks except the last one directly
                // into outBuff. The last block is decrypted into a temporary buffer so we can
                // strip padding before copying the unpadded portion to outBuff. This avoids
                // writing beyond the caller's output buffer (which may be sized for the
                // unpadded plaintext, not the block-aligned ciphertext).
                int blockSize = engine.getBlockSize();

                if (inLength > blockSize) {
                    // Decrypt all but the last block directly into the output buffer.
                    int leadingLen = inLength - blockSize;
                    total = (short) engine.processBytes(inBuff, inOffset, leadingLen, outBuff, outOffset);

                    // Decrypt the last block into a temporary buffer for padding removal.
                    byte[] lastBlock = new byte[blockSize];
                    int lastProcessed = engine.processBytes(inBuff, (short)(inOffset + leadingLen), blockSize, lastBlock, 0);
                    lastProcessed += engine.doFinal(lastBlock, lastProcessed);

                    // Strip padding and copy the unpadded remainder to the output.
                    int padCount = padding.padCount(lastBlock);
                    int usefulBytes = lastProcessed - padCount;
                    if (usefulBytes > 0) {
                        System.arraycopy(lastBlock, 0, outBuff, outOffset + total, usefulBytes);
                    }
                    total += (short) usefulBytes;
                } else {
                    // Single block: decrypt into temp buffer, strip padding, copy out.
                    byte[] lastBlock = new byte[blockSize];
                    int lastProcessed = engine.processBytes(inBuff, inOffset, inLength, lastBlock, 0);
                    lastProcessed += engine.doFinal(lastBlock, lastProcessed);

                    int padCount = padding.padCount(lastBlock);
                    total = (short) (lastProcessed - padCount);
                    if (total > 0) {
                        System.arraycopy(lastBlock, 0, outBuff, outOffset, total);
                    }
                }

            } else {
                // UNPADDED: pass through directly to the engine.
                total = (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
                total += (short) engine.doFinal(outBuff, outOffset + total);
            }

            if (log.isDebugEnabled()) {
                StringBuilder sb = new StringBuilder();
                sb.append("doFinal result outLen=").append(total).append(" out=");
                for (int i = outOffset; i < outOffset + total; i++) sb.append(String.format("%02X", outBuff[i]));
                log.debug(sb.toString());
            }
            return total;
        } catch (CryptoException ce) {
            throw ce;
        } catch (Exception ex) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    /**
     * Processes intermediate cipher data. All complete blocks are output immediately.
     *
     * <p>Because padded algorithms use an unpadded {@link BufferedBlockCipher} internally,
     * {@code update()} behaves identically for padded and unpadded algorithms: every
     * complete block of input produces a corresponding block of output with no hold-back.
     * This matches the JavaCard specification's contract for {@link Cipher#update}.
     */
    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        return (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    /**
     * Selects the appropriate BouncyCastle cipher engine and padding strategy based on the algorithm.
     *
     * <p>For padded algorithms, the engine is always an <em>unpadded</em> {@link BufferedBlockCipher}
     * and the {@link #padding} field is set to the corresponding {@link BlockCipherPadding} instance.
     * Padding is then applied/removed in {@link #doFinal} rather than by the engine itself.
     * See the class-level documentation for the rationale.
     */
    private void selectCipherEngine(Key theKey) {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!(theKey instanceof SymmetricKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (!checkKeyCompatibility(theKey)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        SymmetricKeyImpl key = (SymmetricKeyImpl) theKey;

        // Reset padding — will be set below for padded algorithms only.
        padding = null;

        switch (algorithm) {
            // --- Unpadded CBC ---
            case ALG_DES_CBC_NOPAD:
            case ALG_AES_BLOCK_128_CBC_NOPAD:
            case ALG_KOREAN_SEED_CBC_NOPAD:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                break;

            // --- Padded CBC: use unpadded engine + manual padding in doFinal ---
            case ALG_DES_CBC_ISO9797_M1:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                padding = new ZeroBytePadding();
                break;
            case ALG_DES_CBC_ISO9797_M2:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                padding = new ISO7816d4Padding();
                break;
            case ALG_DES_CBC_PKCS5:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                padding = new PKCS7Padding();
                break;
            case ALG_AES_CBC_ISO9797_M2:
                engine = new BufferedBlockCipher(CBCBlockCipher.newInstance(key.getCipher()));
                padding = new ISO7816d4Padding();
                break;

            // --- Unpadded ECB ---
            case ALG_DES_ECB_NOPAD:
            case ALG_AES_BLOCK_128_ECB_NOPAD:
            case ALG_KOREAN_SEED_ECB_NOPAD:
                engine = new BufferedBlockCipher(key.getCipher());
                break;

            // --- Padded ECB: use unpadded engine + manual padding in doFinal ---
            case ALG_DES_ECB_ISO9797_M1:
                engine = new BufferedBlockCipher(key.getCipher());
                padding = new ZeroBytePadding();
                break;
            case ALG_DES_ECB_ISO9797_M2:
                engine = new BufferedBlockCipher(key.getCipher());
                padding = new ISO7816d4Padding();
                break;
            case ALG_DES_ECB_PKCS5:
                engine = new BufferedBlockCipher(key.getCipher());
                padding = new PKCS7Padding();
                break;

            // --- CTR mode (no padding) ---
            case ALG_AES_CTR:
                engine = new BufferedBlockCipher(new SICBlockCipher(key.getCipher()));
                break;

            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
    }

    private boolean checkKeyCompatibility(Key theKey) {
        switch (theKey.getType()) {
            case KeyBuilder.TYPE_DES:
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_DES_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_DES_CBC_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_DES_CBC_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_DES_CBC_PKCS5) ||
                    (algorithm == Cipher.ALG_DES_ECB_NOPAD) ||
                    (algorithm == Cipher.ALG_DES_ECB_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_DES_ECB_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_DES_ECB_PKCS5)) {
                    return true;
                }
                break;

            case KeyBuilder.TYPE_AES:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_AES_CTR) ||
                    (algorithm == Cipher.ALG_AES_BLOCK_128_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_AES_BLOCK_128_ECB_NOPAD) ||
                    (algorithm == Cipher.ALG_AES_CBC_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_AES_CBC_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_AES_CBC_PKCS5) ||
                    (algorithm == Cipher.ALG_AES_ECB_ISO9797_M1) ||
                    (algorithm == Cipher.ALG_AES_ECB_ISO9797_M2) ||
                    (algorithm == Cipher.ALG_AES_ECB_PKCS5)) {
                    return true;
                }
                break;


            case KeyBuilder.TYPE_KOREAN_SEED:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT:
                if ((algorithm == Cipher.ALG_KOREAN_SEED_CBC_NOPAD) ||
                    (algorithm == Cipher.ALG_KOREAN_SEED_ECB_NOPAD)) {
                    return true;
                }
                break;
        }

        return false;

    }

    public byte getPaddingAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte getCipherAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
