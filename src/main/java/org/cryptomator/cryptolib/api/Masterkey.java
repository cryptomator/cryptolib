package org.cryptomator.cryptolib.api;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.security.SecureRandom;
import java.util.Arrays;

public class Masterkey extends DestroyableSecretKey {

	private static final String KEY_ALGORITHM = "MASTERKEY";
	public static final String ENC_ALG = "AES";
	public static final String MAC_ALG = "HmacSHA256";
	public static final int SUBKEY_LEN_BYTES = 32;

	public Masterkey(byte[] key) {
		super(checkKeyLength(key), KEY_ALGORITHM);
	}

	private static byte[] checkKeyLength(byte[] key) {
		Preconditions.checkArgument(key.length == SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES, "Invalid raw key length %s", key.length);
		return key;
	}

	public static Masterkey generate(SecureRandom csprng) {
		byte[] key = new byte[SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES];
		try {
			csprng.nextBytes(key);
			return new Masterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	@Override
	public Masterkey clone() {
		return new Masterkey(getEncoded());
	}

	public DestroyableSecretKey getEncKey() {
		return new DestroyableSecretKey(getEncoded(), 0, SUBKEY_LEN_BYTES, ENC_ALG);
	}

	public DestroyableSecretKey getMacKey() {
		return new DestroyableSecretKey(getEncoded(), SUBKEY_LEN_BYTES, SUBKEY_LEN_BYTES, MAC_ALG);
	}

}
