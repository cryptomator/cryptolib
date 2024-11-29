package org.cryptomator.cryptolib.api;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

public class PerpetualMasterkey implements Masterkey {

	public static final String ENC_ALG = "AES";
	public static final String MAC_ALG = "HmacSHA256";
	public static final int SUBKEY_LEN_BYTES = 32;

	private final transient byte[] key;
	private boolean destroyed;

	public PerpetualMasterkey(byte[] key) {
		Preconditions.checkArgument(key.length == SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES, "Invalid raw key length %s", key.length);
		this.key = new byte[key.length];
		this.destroyed = false;
		System.arraycopy(key, 0, this.key, 0, key.length);
	}

	public static PerpetualMasterkey generate(SecureRandom csprng) {
		byte[] key = new byte[SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES];
		try {
			csprng.nextBytes(key);
			return new PerpetualMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	public static PerpetualMasterkey from(DestroyableSecretKey encKey, DestroyableSecretKey macKey) {
		Preconditions.checkArgument(encKey.getEncoded().length == SUBKEY_LEN_BYTES, "Invalid key length of encKey");
		Preconditions.checkArgument(macKey.getEncoded().length == SUBKEY_LEN_BYTES, "Invalid key length of macKey");
		byte[] key = new byte[SUBKEY_LEN_BYTES + SUBKEY_LEN_BYTES];
		try {
			System.arraycopy(encKey.getEncoded(), 0, key, 0, SUBKEY_LEN_BYTES);
			System.arraycopy(macKey.getEncoded(), 0, key, SUBKEY_LEN_BYTES, SUBKEY_LEN_BYTES);
			return new PerpetualMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	public Masterkey copy() {
		return new PerpetualMasterkey(key);
	}

	/**
	 * Get the encryption subkey.
	 *
	 * @return A new copy of the subkey used for encryption
	 */
	public DestroyableSecretKey getEncKey() {
		return new DestroyableSecretKey(key, 0, SUBKEY_LEN_BYTES, ENC_ALG);
	}

	/**
	 * Get the MAC subkey.
	 *
	 * @return A new copy of the subkey used for message authentication
	 */
	public DestroyableSecretKey getMacKey() {
		return new DestroyableSecretKey(key, SUBKEY_LEN_BYTES, SUBKEY_LEN_BYTES, MAC_ALG);
	}

	@Override
	public boolean isDestroyed() {
		return destroyed;
	}

	@Override
	public void destroy() {
		Arrays.fill(key, (byte) 0x00);
		destroyed = true;
	}

	public byte[] getEncoded() {
		return key;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		PerpetualMasterkey that = (PerpetualMasterkey) o;
		return MessageDigest.isEqual(this.key, that.key);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(key);
	}

}
