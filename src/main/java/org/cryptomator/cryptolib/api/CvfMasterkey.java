package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.security.SecureRandom;
import java.util.Arrays;

public class CvfMasterkey extends DestroyableSecretKey {

	private static final String KEY_ALGORITHM = "MASTERKEY";
	public static final String ENC_ALG = "AES";
	public static final String MAC_ALG = "HmacSHA256";
	public static final int SUBKEY_LEN_BYTES = 32;

	public CvfMasterkey(byte[] key) {
		super(checkKeyLength(key), KEY_ALGORITHM);
	}

	private static byte[] checkKeyLength(byte[] key) {
		if (key.length != SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES) {
			throw new IllegalArgumentException(String.format("Invalid raw key length %s", key.length));
		}
		return key;
	}

	public static CvfMasterkey generate(SecureRandom csprng) {
		byte[] key = new byte[SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES];
		try {
			csprng.nextBytes(key);
			return new CvfMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	public static CvfMasterkey from(DestroyableSecretKey encKey, DestroyableSecretKey macKey) {
		if (encKey.getEncoded().length != SUBKEY_LEN_BYTES) {
			throw new IllegalArgumentException("Invalid key length of encKey");
		}
		if (macKey.getEncoded().length != SUBKEY_LEN_BYTES) {
			throw new IllegalArgumentException("Invalid key length of macKey");
		}
		byte[] key = new byte[SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES];
		try {
			System.arraycopy(encKey.getEncoded(), 0, key, 0, SUBKEY_LEN_BYTES);
			System.arraycopy(macKey.getEncoded(), 0, key, SUBKEY_LEN_BYTES, SUBKEY_LEN_BYTES);
			return new CvfMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	@Override
	public CvfMasterkey copy() {
		return new CvfMasterkey(getEncoded());
	}

	/**
	 * Get the encryption subkey.
	 *
	 * @return A new copy of the subkey used for encryption
	 */
	public DestroyableSecretKey getEncKey() {
		return new DestroyableSecretKey(getEncoded(), 0, SUBKEY_LEN_BYTES, ENC_ALG);
	}

	/**
	 * Get the MAC subkey.
	 *
	 * @return A new copy of the subkey used for message authentication
	 */
	public DestroyableSecretKey getMacKey() {
		return new DestroyableSecretKey(getEncoded(), SUBKEY_LEN_BYTES, SUBKEY_LEN_BYTES, MAC_ALG);
	}

}
