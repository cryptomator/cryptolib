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
 * 	Masterkey masterkey;
 * 	try (MasterkeyLoader loader = MasterkeyFile.withContent(in).unlock(pw, pepper, expectedVaultVersion)) {
 * 		masterkey = loader.loadKey(MasterkeyFileLoader.KEY_ID);
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

	@Override
	public Masterkey loadKey(String keyId) throws MasterkeyLoadingFailedException {
		if (!KEY_ID.equals(keyId)) {
			throw new MasterkeyLoadingFailedException("Unsupported key " + keyId);
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
