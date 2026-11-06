package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;

public interface RevolvingMasterkey extends Masterkey {

	/**
	 * Returns a subkey for the given revision and usage context.
	 * @param revision Key revision
	 * @param length Desired key length in bytes
	 * @param context Usage context to distinguish subkeys
	 * @param algorithm The name of the {@link javax.crypto.SecretKey#getAlgorithm() algorithm} associated with the generated subkey
	 * @return A subkey specificially for the given revision and context
	 */
	DestroyableSecretKey subKey(int revision, int length, byte[] context, String algorithm);

	int firstRevision();

	int currentRevision();
}
