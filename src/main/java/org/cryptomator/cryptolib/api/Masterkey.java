package org.cryptomator.cryptolib.api;

import com.google.common.base.Preconditions;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import javax.security.auth.Destroyable;
import java.security.SecureRandom;
import java.util.Arrays;

public interface Masterkey extends Destroyable, AutoCloseable {

	static PerpetualMasterkey generate(SecureRandom csprng) {
		byte[] key = new byte[PerpetualMasterkey.SUBKEY_LEN_BYTES + PerpetualMasterkey.SUBKEY_LEN_BYTES];
		try {
			csprng.nextBytes(key);
			return new PerpetualMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	static PerpetualMasterkey from(DestroyableSecretKey encKey, DestroyableSecretKey macKey) {
		Preconditions.checkArgument(encKey.getEncoded().length == PerpetualMasterkey.SUBKEY_LEN_BYTES, "Invalid key length of encKey");
		Preconditions.checkArgument(macKey.getEncoded().length == PerpetualMasterkey.SUBKEY_LEN_BYTES, "Invalid key length of macKey");
		byte[] key = new byte[PerpetualMasterkey.SUBKEY_LEN_BYTES + PerpetualMasterkey.SUBKEY_LEN_BYTES];
		try {
			System.arraycopy(encKey.getEncoded(), 0, key, 0, PerpetualMasterkey.SUBKEY_LEN_BYTES);
			System.arraycopy(macKey.getEncoded(), 0, key, PerpetualMasterkey.SUBKEY_LEN_BYTES, PerpetualMasterkey.SUBKEY_LEN_BYTES);
			return new PerpetualMasterkey(key);
		} finally {
			Arrays.fill(key, (byte) 0x00);
		}
	}

	@Override
	void destroy();

	/**
	 * Same as {@link #destroy()}
	 */
	@Override
	default void close() {
		destroy();
	}

}
