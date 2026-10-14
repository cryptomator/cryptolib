package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.common.WordEncoder;

import java.util.Arrays;
import java.util.zip.CRC32;

/**
 * The word encoding of recovery keys shared with Cryptomator and Cryptomator Hub: key bytes, followed by the two least significant bytes of their CRC32 (least significant first)
 * and, for variable-length keys, one to three padding bytes whose value is the padding length.
 */
public final class RecoveryKeys {

	private static final int CHECKSUM_LEN = 2;

	private RecoveryKeys() {
	}

	/**
	 * Encodes a key as words.
	 *
	 * @param key The key bytes
	 * @param pad Whether to append padding bytes (for keys whose length plus checksum is not a multiple of three, e.g. PKCS#8 keys); fixed-size formats such as the CVF8 masterkey use none
	 * @return The recovery key as words
	 * @throws IllegalArgumentException If {@code pad} is {@code false} and the length is not encodable
	 */
	public static String encode(byte[] key, boolean pad) {
		int paddingLen = pad ? 3 - (key.length + CHECKSUM_LEN) % 3 : 0;
		byte[] padded = Arrays.copyOf(key, key.length + CHECKSUM_LEN + paddingLen);
		try {
			long crc = crc32(key);
			padded[key.length] = (byte) (crc & 0xFF);
			padded[key.length + 1] = (byte) ((crc >> 8) & 0xFF);
			Arrays.fill(padded, key.length + CHECKSUM_LEN, padded.length, (byte) paddingLen);
			return WordEncoder.ENGLISH.encodePadded(padded);
		} finally {
			Arrays.fill(padded, (byte) 0x00);
		}
	}

	/**
	 * Decodes and verifies a recovery key.
	 *
	 * @param recoveryKey The words, separated by whitespace
	 * @param padded Whether the encoding carries padding bytes, see {@link #encode(byte[], boolean)}
	 * @return The key bytes
	 * @throws IllegalArgumentException If the words are not a valid recovery key (unknown word, odd word count, invalid padding or checksum)
	 */
	public static byte[] decode(CharSequence recoveryKey, boolean padded) {
		byte[] decoded = WordEncoder.ENGLISH.decode(recoveryKey.toString());
		try {
			int paddingLen = 0;
			if (padded) {
				paddingLen = decoded.length == 0 ? 0 : decoded[decoded.length - 1];
				if (paddingLen < 1 || paddingLen > 3 || decoded.length < paddingLen) {
					throw new IllegalArgumentException("Invalid padding");
				}
			}
			int keyLen = decoded.length - paddingLen - CHECKSUM_LEN;
			if (keyLen < 0) {
				throw new IllegalArgumentException("Invalid recovery key length");
			}
			byte[] key = Arrays.copyOf(decoded, keyLen);
			long crc = crc32(key);
			if (decoded[keyLen] != (byte) (crc & 0xFF) || decoded[keyLen + 1] != (byte) ((crc >> 8) & 0xFF)) {
				Arrays.fill(key, (byte) 0x00);
				throw new IllegalArgumentException("Invalid recovery key checksum");
			}
			return key;
		} finally {
			Arrays.fill(decoded, (byte) 0x00);
		}
	}

	private static long crc32(byte[] bytes) {
		CRC32 crc = new CRC32();
		crc.update(bytes);
		return crc.getValue();
	}

}
