package org.cryptomator.cryptolib.api;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

public class Masterkey implements AutoCloseable, SecretKey, Cloneable {

	public static final String ENC_ALG = "AES";
	public static final String MAC_ALG = "HmacSHA256";
	public static final int KEY_LEN_BYTES = 32;

	private final DestroyableSecretKey encKey;
	private final DestroyableSecretKey macKey;

	public Masterkey(SecretKey encKey, SecretKey macKey) {
		this(DestroyableSecretKey.from(encKey), DestroyableSecretKey.from(macKey));
	}

	public Masterkey(DestroyableSecretKey encKey, DestroyableSecretKey macKey) {
		this.encKey = Preconditions.checkNotNull(encKey);
		this.macKey = Preconditions.checkNotNull(macKey);
	}

	public static Masterkey createNew(SecureRandom random) {
		DestroyableSecretKey encKey = DestroyableSecretKey.generate(random, ENC_ALG, KEY_LEN_BYTES);
		DestroyableSecretKey macKey = DestroyableSecretKey.generate(random, MAC_ALG, KEY_LEN_BYTES);
		return new Masterkey(encKey, macKey);
	}

	public static Masterkey createFromRaw(byte[] encoded) {
		Preconditions.checkArgument(encoded.length == KEY_LEN_BYTES + KEY_LEN_BYTES, "Invalid raw key length %s", encoded.length);
		DestroyableSecretKey encKey = new DestroyableSecretKey(encoded, 0, KEY_LEN_BYTES, ENC_ALG);
		DestroyableSecretKey macKey = new DestroyableSecretKey(encoded, KEY_LEN_BYTES, KEY_LEN_BYTES, MAC_ALG);
		return new Masterkey(encKey, macKey);
	}

	/**
	 * Creates an exact deep copy of this Masterkey.
	 * The new instance is decoupled from this instance and will therefore survive if this gets destroyed.
	 *
	 * @return A new but equal Masterkey instance
	 */
	@Override
	public Masterkey clone() {
		return Masterkey.createFromRaw(getEncoded());
	}

	public SecretKey getEncKey() {
		return encKey;
	}

	public SecretKey getMacKey() {
		return macKey;
	}

	@Override
	public String getAlgorithm() {
		return "private";
	}

	@Override
	public String getFormat() {
		return "RAW";
	}

	@Override
	public byte[] getEncoded() {
		byte[] rawEncKey = encKey.getEncoded();
		byte[] rawMacKey = macKey.getEncoded();
		try {
			byte[] rawKey = new byte[rawEncKey.length + rawMacKey.length];
			System.arraycopy(rawEncKey, 0, rawKey, 0, rawEncKey.length);
			System.arraycopy(rawMacKey, 0, rawKey, rawEncKey.length, rawMacKey.length);
			return rawKey;
		} finally {
			Arrays.fill(rawEncKey, (byte) 0x00);
			Arrays.fill(rawMacKey, (byte) 0x00);
		}
	}

	@Override
	public void close() {
		destroy();
	}

	@Override
	public boolean isDestroyed() {
		return encKey.isDestroyed() && macKey.isDestroyed();
	}

	@Override
	public void destroy() {
		encKey.destroy();
		macKey.destroy();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Masterkey masterkey = (Masterkey) o;
		return encKey.equals(masterkey.encKey) && macKey.equals(masterkey.macKey);
	}

	@Override
	public int hashCode() {
		return Objects.hash(encKey, macKey);
	}
}
