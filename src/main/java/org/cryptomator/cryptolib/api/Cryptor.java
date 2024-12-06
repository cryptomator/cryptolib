package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;

public interface Cryptor extends Destroyable, AutoCloseable {

	/**
	 * Encryption and decryption of file content.
	 * @return utility for encrypting and decrypting file content
	 */
	FileContentCryptor fileContentCryptor();

	/**
	 * Encryption and decryption of file headers.
	 * @return utility for encrypting and decrypting file headers
	 */
	FileHeaderCryptor fileHeaderCryptor();

	/**
	 * Encryption and decryption of file names in Cryptomator Vault Format.
	 * @return utility for encrypting and decrypting file names
	 * @apiNote Only relevant for Cryptomator Vault Format, for Universal Vault Format see {@link #fileNameCryptor(int)}
	 */
	FileNameCryptor fileNameCryptor();

	/**
	 * Encryption and decryption of file names in Universal Vault Format.
	 * @param revision The revision of the seed to {@link RevolvingMasterkey#subKey(int, int, byte[], String) derive subkeys}.
	 * @return utility for encrypting and decrypting file names
	 * @apiNote Only relevant for Universal Vault Format, for Cryptomator Vault Format see {@link #fileNameCryptor()}
	 */
	FileNameCryptor fileNameCryptor(int revision);

	@Override
	void destroy();

	/**
	 * Calls {@link #destroy()}.
	 */
	@Override
	default void close() {
		destroy();
	}

}
