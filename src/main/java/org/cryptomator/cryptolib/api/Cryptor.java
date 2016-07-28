package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;

public interface Cryptor extends Destroyable {

	public FileContentCryptor fileContentCryptor();

	public FileHeaderCryptor fileHeaderCryptor();

	public FileNameCryptor fileNameCryptor();

	/**
	 * @param passphrase The passphrase used to encrypt the key material.
	 * @param vaultVersion Will be checked upon decryption of this masterkey.
	 * @return Encrypted data that can be stored in insecure locations.
	 */
	public byte[] writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion);

}
