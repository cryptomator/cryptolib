package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Optional;

/**
 * Instances of this class can be retrieved by {@link MasterkeyFile#unlock(CharSequence, byte[], Optional) unlocking}
 * a Cryptomator masterkey file and then be used to {@link MasterkeyLoader#loadKey(String) load} a {@link Masterkey}.
 *
 * <pre>
 * 	try (Masterkey masterkey = MasterkeyFile.withContent(in).unlock(pw, pepper, expectedVaultVersion).loadKeyAndClose()) {
 * 		// use masterkey
 * 	}
 * </pre>
 */
public class MasterkeyFileLoader implements MasterkeyLoader, AutoCloseable {

	public static final String KEY_ID = "MASTERKEY_FILE";
	private final SecretKey encKey;
	private final SecretKey macKey;

	// intentionally package-private
	MasterkeyFileLoader(SecretKey encKey, SecretKey macKey) {
		this.encKey = encKey;
		this.macKey = macKey;
	}

	/**
	 * Loads the key and closes this MasterkeyFileLoader immediately, if reuse is not required.
	 *
	 * @return The masterkey loaded from this masterkey file.
	 */
	public Masterkey loadKeyAndClose() {
		try {
			return loadKey();
		} finally {
			close();
		}
	}

	/**
	 * @return The masterkey loaded from this masterkey file.
	 */
	public Masterkey loadKey() {
		try {
			return loadKey(KEY_ID);
		} catch (MasterkeyLoadingFailedException e) {
			throw new IllegalStateException("Should have been able to load " + KEY_ID);
		}
	}

	@Override
	public Masterkey loadKey(String keyId) throws MasterkeyLoadingFailedException {
		if (!KEY_ID.equals(keyId)) {
			throw new MasterkeyLoadingFailedException("Unsupported key " + keyId);
		}
		if (encKey.isDestroyed() || macKey.isDestroyed()) {
			throw new MasterkeyLoadingFailedException("MasterkeyFileLoader already closed.");
		}
		// we need a copy to make sure we can use autocloseable destruction
		SecretKey encKeyCopy = new SecretKeySpec(encKey.getEncoded(), encKey.getAlgorithm());
		SecretKey macKeyCopy = new SecretKeySpec(macKey.getEncoded(), macKey.getAlgorithm());
		return new Masterkey(encKeyCopy, macKeyCopy);
	}

	@Override
	public void close() {
		Destroyables.destroySilently(encKey);
		Destroyables.destroySilently(macKey);
	}

}
