package org.cryptomator.cryptolib.api;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.common.Destroyables;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class Masterkey implements AutoCloseable, SecretKey {

	public static final String ENC_ALG = "AES";
	public static final String MAC_ALG = "HmacSHA256";
	public static final int KEY_LEN_BYTES = 32;

	private final SecretKey encKey;
	private final SecretKey macKey;

	public Masterkey(SecretKey encKey, SecretKey macKey) {
		this.encKey = encKey;
		this.macKey = macKey;
	}

	public static Masterkey createNew(SecureRandom random) {
		try {
			KeyGenerator encKeyGen = KeyGenerator.getInstance(ENC_ALG);
			encKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
			SecretKey encKey = encKeyGen.generateKey();
			KeyGenerator macKeyGen = KeyGenerator.getInstance(MAC_ALG);
			macKeyGen.init(KEY_LEN_BYTES * Byte.SIZE, random);
			SecretKey macKey = macKeyGen.generateKey();
			return new Masterkey(encKey, macKey);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Hard-coded algorithm doesn't exist.", e);
		}
	}

	public static Masterkey createFromRaw(byte[] encoded) {
		Preconditions.checkArgument(encoded.length == KEY_LEN_BYTES + KEY_LEN_BYTES, "Invalid raw key length %s", encoded.length);
		SecretKey encKey = new SecretKeySpec(encoded, 0, KEY_LEN_BYTES, ENC_ALG);
		SecretKey macKey = new SecretKeySpec(encoded, KEY_LEN_BYTES, KEY_LEN_BYTES, MAC_ALG);
		return new Masterkey(encKey, macKey);
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
		Destroyables.destroySilently(encKey);
		Destroyables.destroySilently(macKey);
	}

}
