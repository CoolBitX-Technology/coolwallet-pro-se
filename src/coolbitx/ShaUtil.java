/*
 * Copyright (C) CoolBitX Technology - All Rights Reserved
 * Unauthorized copying of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package coolbitx;

import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * 
 * @author Hank Liu <hankliu@coolbitx.com>
 */
public final class ShaUtil {

	static MessageDigest m_sha_1;
	static MessageDigest m_sha_256;
	static MessageDigest m_sha_512;
	static MessageDigest m_sha_512_256;
	static MessageDigest m_s_sha_256; // only for script
	static Blake2b m_blake2b_256;
	static Blake2b m_blake2b_512;
	static MessageDigest m_blake3_256;
	static MessageDigest m_sha3_256;
	static MessageDigest m_sha3_512;
	static MessageDigest m_keccak_256;
	static MessageDigest m_keccak_512;

	public static void init() {
		m_sha_1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
		m_sha_256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		m_s_sha_256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256,
				false);
		m_sha_512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
		m_sha_512_256 = Sha2.getInstance(Sha2.ALG_SHA_512_256);
		m_blake2b_256 = Blake2b.getInstance(Blake2b.ALG_BLAKE2B, (byte) 32);
		m_blake2b_512 = Blake2b.getInstance(Blake2b.ALG_BLAKE2B, (byte) 64);
		m_blake3_256 = Blake3.getInstance(Blake3.ALG_BLAKE3, (byte) 32);
		m_sha3_256 = Sha3.getInstance(Sha3.ALG_SHA3_256);
		m_sha3_512 = Sha3.getInstance(Sha3.ALG_SHA3_512);
		m_keccak_256 = Sha3.getInstance(Sha3.ALG_KECCAK_256);
		m_keccak_512 = Sha3.getInstance(Sha3.ALG_KECCAK_512);
	}

	public static void uninit() {
		m_sha_1 = null;
		m_sha_256 = null;
		m_sha_512 = null;
		m_sha_512_256 = null;
		m_s_sha_256 = null;
		m_blake2b_256 = null;
		m_blake2b_512 = null;
		m_blake3_256 = null;
		m_sha3_256 = null;
		m_sha3_512 = null;
		m_keccak_256 = null;
		m_keccak_512 = null;
	}

	public final static short SHA1(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha_1.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short SHA256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short S_SHA256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_s_sha_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short DoubleSHA256(byte[] buf, short offset,
			short length, byte[] destbuf, short destOffset) {
		short len = m_sha_256.doFinal(buf, offset, length, destbuf, destOffset);
		len = m_sha_256.doFinal(destbuf, destOffset, len, destbuf, destOffset);
		return len;
	}

	public final static short S_DoubleSHA256(byte[] buf, short offset,
			short length, byte[] destbuf, short destOffset) {
		short len = m_s_sha_256.doFinal(buf, offset, length, destbuf,
				destOffset);
		len = m_s_sha_256
				.doFinal(destbuf, destOffset, len, destbuf, destOffset);
		return len;
	}

	public final static short SHA512(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha_512.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short SHA512256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha_512_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short Keccak256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_keccak_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short Keccak512(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_keccak_512.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short Sha3256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha3_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short Sha3512(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_sha3_512.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public static short CRC16(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset) {
		short crc = 0;
		for (short i = 0; i < length; ++i) {
			short code = (short) (((crc >> 8) ^ buf[(short) (i + offset)]) & 0xff);

			crc <<= 8;
			crc ^= (code ^= code >>> 4) ^ (code <<= 5) ^ (code <<= 7);
		}
		Util.setShort(destBuf, destOffset, crc);
		return 2;
	}

	public static short polyMod(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset) {
		byte[] apdu = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workOffset = WorkCenter.getWorkspaceOffset((short) 6);

		apdu[(short) (workOffset + 5)] = 1;
		for (short i = 0; i < length; i++) {
			MathUtil.shiftLeftFixed(apdu, workOffset, (short) 6, apdu,
					workOffset, (byte) 5);
			apdu[(short) (workOffset + 5)] ^= buf[(short) (offset + i)];

			for (byte j = 0; j < 5; j++) {
				if (((apdu[(short) (workOffset)] >> j) & 1) == 1) {
					MathUtil.xor(apdu, (short) (workOffset + 1), (short) 5,
							GENERATOR, (short) (j * 5), apdu,
							(short) (workOffset + 1));
				}

			}
		}
		apdu[(short) (workOffset + 5)] ^= 1;
		Util.arrayCopyNonAtomic(apdu, (short) (workOffset + 1), destBuf,
				destOffset, (short) 5);
		WorkCenter.release(WorkCenter.WORK, (short) 6);
		return (short) 5;
	}

	public static short bech32m_checksum(byte[] buf, short offset,
			short length, byte[] destBuf, short destOffset) {
		bech32_polyMod(buf, offset, length, destBuf, destOffset);
		destBuf[destOffset] ^= (byte) 0x2b;
		destBuf[(short) (destOffset + 1)] ^= (byte) 0xc8;
		destBuf[(short) (destOffset + 2)] ^= (byte) 0x30;
		destBuf[(short) (destOffset + 3)] ^= (byte) 0xa3;
		return (short) 4;
	}

	public static short bech32_checksum(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset) {
		bech32_polyMod(buf, offset, length, destBuf, destOffset);
		destBuf[(short) (destOffset + 3)] ^= 1;
		return (short) 4;
	}

	public static short bech32_polyMod(byte[] buf, short offset, short length,
			byte[] destBuf, short destOffset) {
		byte[] apdu = WorkCenter.getWorkspaceArray(WorkCenter.WORK);
		short workOffset = WorkCenter.getWorkspaceOffset((short) 5);

		apdu[(short) (workOffset + 4)] = 1;
		for (short i = 0; i < length; i++) {
			MathUtil.shiftLeftFixed(apdu, workOffset, (short) 5, apdu,
					workOffset, (byte) 5);
			apdu[(short) (workOffset + 4)] ^= buf[(short) (offset + i)];
			if (((apdu[(short) (workOffset + 1)] >> 6) & 1) == 1) {
				MathUtil.xor(apdu, (short) (workOffset + 1), (short) 4,
						BECH32_GENERATOR, (short) 0, apdu,
						(short) (workOffset + 1));
			}
			if (((apdu[(short) (workOffset + 1)] >> 7) & 1) == 1) {
				MathUtil.xor(apdu, (short) (workOffset + 1), (short) 4,
						BECH32_GENERATOR, (short) 4, apdu,
						(short) (workOffset + 1));
			}
			if (((apdu[(short) (workOffset)] >> 0) & 1) == 1) {
				MathUtil.xor(apdu, (short) (workOffset + 1), (short) 4,
						BECH32_GENERATOR, (short) 8, apdu,
						(short) (workOffset + 1));
			}
			if (((apdu[(short) (workOffset)] >> 1) & 1) == 1) {
				MathUtil.xor(apdu, (short) (workOffset + 1), (short) 4,
						BECH32_GENERATOR, (short) 12, apdu,
						(short) (workOffset + 1));
			}
			if (((apdu[(short) (workOffset)] >> 2) & 1) == 1) {
				MathUtil.xor(apdu, (short) (workOffset + 1), (short) 4,
						BECH32_GENERATOR, (short) 16, apdu,
						(short) (workOffset + 1));
			}
		}
		apdu[(short) (workOffset + 1)] &= 0x3f;
		// apdu[(short) (workOffset + 4)] ^= 1;
		Util.arrayCopyNonAtomic(apdu, (short) (workOffset + 1), destBuf,
				destOffset, (short) 4);
		WorkCenter.release(WorkCenter.WORK, (short) 5);
		return (short) 4;
	}

	public final static short Blake2b256(byte[] buf, short offset,
			short length, byte[] destbuf, short destOffset) {
		return m_blake2b_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	public final static short Blake2b256(byte[] buf, short offset,
			short length, byte[] key, short keyOffset, byte keyLength,
			byte[] destbuf, short destOffset) {
		return m_blake2b_256.doFinal(buf, offset, length, key, keyOffset,
				keyLength, destbuf, destOffset);
	}

	public final static short Blake2b512(byte[] buf, short offset,
			short length, byte[] destbuf, short destOffset) {
		return m_blake2b_512.doFinal(buf, offset, length, destbuf, destOffset);
	}
	
	public final static short Blake2b512(byte[] buf, short offset,
			short length, byte[] key, short keyOffset, byte keyLength,
			byte[] destbuf, short destOffset) {
		return m_blake2b_512.doFinal(buf, offset, length, key, keyOffset,
				keyLength, destbuf, destOffset);
	}

	public final static short Blake3256(byte[] buf, short offset, short length,
			byte[] destbuf, short destOffset) {
		return m_blake3_256.doFinal(buf, offset, length, destbuf, destOffset);
	}

	private static final byte[] GENERATOR = { (byte) 0x98, (byte) 0xf2,
			(byte) 0xbc, (byte) 0x8e, (byte) 0x61, (byte) 0x79, (byte) 0xb7,
			(byte) 0x6d, (byte) 0x99, (byte) 0xe2, (byte) 0xf3, (byte) 0x3e,
			(byte) 0x5f, (byte) 0xb3, (byte) 0xc4, (byte) 0xae, (byte) 0x2e,
			(byte) 0xab, (byte) 0xe2, (byte) 0xa8, (byte) 0x1e, (byte) 0x4f,
			(byte) 0x43, (byte) 0xe4, (byte) 0x70 };

	private static final byte[] BECH32_GENERATOR = { (byte) 0x3b, (byte) 0x6a,
			(byte) 0x57, (byte) 0xb2, (byte) 0x26, (byte) 0x50, (byte) 0x8e,
			(byte) 0x6d, (byte) 0x1e, (byte) 0xa1, (byte) 0x19, (byte) 0xfa,
			(byte) 0x3d, (byte) 0x42, (byte) 0x33, (byte) 0xdd, (byte) 0x2a,
			(byte) 0x14, (byte) 0x62, (byte) 0xb3 };

}
