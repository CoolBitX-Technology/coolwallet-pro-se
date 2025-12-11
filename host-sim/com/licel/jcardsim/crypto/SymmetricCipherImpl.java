/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.licel.jcardsim.crypto;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacardx.crypto.Cipher;

// 使用標準 JavaCard 介面來取 Key
import javacard.security.AESKey;
import javacard.security.DESKey;

// Bouncy Castle Imports (使用標準 org.bouncycastle)
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.ZeroBytePadding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class SymmetricCipherImpl extends Cipher {

    byte algorithm;
    BufferedBlockCipher engine;
    boolean isInitialized;
    byte[] iv;

    public SymmetricCipherImpl(byte algorithm) {
        this.algorithm = algorithm;
        switch (algorithm) {
            case Cipher.ALG_DES_CBC_NOPAD:
                engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()), new ZeroBytePadding());
                break;
            case Cipher.ALG_DES_CBC_ISO9797_M1:
            case Cipher.ALG_DES_CBC_ISO9797_M2:
                engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()), new ZeroBytePadding());
                break;
            case Cipher.ALG_DES_CBC_PKCS5:
                engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()), new PKCS7Padding());
                break;

            case Cipher.ALG_DES_ECB_NOPAD:
                engine = new PaddedBufferedBlockCipher(new DESEngine(), new ZeroBytePadding());
                break;
            case Cipher.ALG_DES_ECB_ISO9797_M1:
            case Cipher.ALG_DES_ECB_ISO9797_M2:
                engine = new PaddedBufferedBlockCipher(new DESEngine(), new ZeroBytePadding());
                break;
            case Cipher.ALG_DES_ECB_PKCS5:
                engine = new PaddedBufferedBlockCipher(new DESEngine(), new PKCS7Padding());
                break;

            case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
                engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new ZeroBytePadding());
                break;
            case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
                engine = new PaddedBufferedBlockCipher(new AESEngine(), new ZeroBytePadding());
                break;

            // =========================================================
            // AES + CBC + PKCS5
            // =========================================================
            case Cipher.ALG_AES_CBC_PKCS5:
                engine = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
                break;
            // =========================================================

            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                break;
        }
    }

    public void init(Key theKey, byte theMode) throws CryptoException {
        init(theKey, theMode, null, (short) 0, (short) 0);
    }

    public void init(Key theKey, byte theMode, byte[] bArray, short bOff, short bLen) throws CryptoException {
        if (theKey == null) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (!theKey.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }

        // --- 修正重點：手動提取 Key Bytes，避開 KeyWithParameters 型別衝突 ---
        byte[] keyData = null;

        if (theKey instanceof AESKey) {
            // 取得 AES Key 長度 (通常 128/192/256 bits)
            int bitLen = theKey.getSize();
            keyData = new byte[bitLen / 8];
            // 使用標準介面取值
            ((AESKey) theKey).getKey(keyData, (short) 0);

        } else if (theKey instanceof DESKey) {
            // 取得 DES Key
            int bitLen = theKey.getSize();
            keyData = new byte[bitLen / 8];
            ((DESKey) theKey).getKey(keyData, (short) 0);

        } else {
            // 如果不是標準 Key (極少見)，則無法處理
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }

        // 建立標準的 Bouncy Castle KeyParameter
        org.bouncycastle.crypto.CipherParameters cipherParams = new KeyParameter(keyData);
        // -----------------------------------------------------------------

        // 處理 IV
        if (bArray != null && bLen > 0) {
            iv = new byte[bLen];
            Util.arrayCopyNonAtomic(bArray, bOff, iv, (short) 0, bLen);
            cipherParams = new ParametersWithIV(cipherParams, iv);
        } else {
            // 自動補零 IV
            if (algorithm == Cipher.ALG_AES_CBC_PKCS5 ||
                    algorithm == Cipher.ALG_AES_BLOCK_128_CBC_NOPAD ||
                    algorithm == Cipher.ALG_DES_CBC_NOPAD ||
                    algorithm == Cipher.ALG_DES_CBC_PKCS5) {

                // 只有當尚未包裝成 ParametersWithIV 才補
                if (!(cipherParams instanceof ParametersWithIV)) {
                    int blockSize = (algorithm == Cipher.ALG_AES_CBC_PKCS5
                            || algorithm == Cipher.ALG_AES_BLOCK_128_CBC_NOPAD) ? 16 : 8;
                    iv = new byte[blockSize];
                    cipherParams = new ParametersWithIV(cipherParams, iv);
                }
            }
        }

        try {
            engine.init(theMode == MODE_ENCRYPT, cipherParams);
        } catch (IllegalArgumentException e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        isInitialized = true;
    }

    public byte getAlgorithm() {
        return algorithm;
    }

    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
            throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        try {
            int processed = engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
            processed += engine.doFinal(outBuff, outOffset + processed);
            return (short) processed;
        } catch (InvalidCipherTextException e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        } catch (Exception e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    public short update(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset)
            throws CryptoException {
        if (!isInitialized) {
            CryptoException.throwIt(CryptoException.INVALID_INIT);
        }
        try {
            return (short) engine.processBytes(inBuff, inOffset, inLength, outBuff, outOffset);
        } catch (Exception e) {
            CryptoException.throwIt(CryptoException.ILLEGAL_USE);
        }
        return -1;
    }

    public byte getPaddingAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte getCipherAlgorithm() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}