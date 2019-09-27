/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;

public interface Cryptor extends Destroyable, AutoCloseable {

	FileContentCryptor fileContentCryptor();

	FileHeaderCryptor fileHeaderCryptor();

	FileNameCryptor fileNameCryptor();

	/**
	 * Shortcut for {@link #writeKeysToMasterkeyFile(CharSequence, byte[], int)} with en empty pepper.
	 * 
	 * @param passphrase The passphrase used to encrypt the key material.
	 * @param vaultVersion Will be checked upon decryption of this masterkey.
	 * @return Encrypted data that can be stored in insecure locations.
	 * @see #writeKeysToMasterkeyFile(CharSequence, byte[], int)
	 */
	KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion);

	/**
	 * @param passphrase The passphrase used to encrypt the key material.
	 * @param pepper An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param vaultVersion Will be checked upon decryption of this masterkey.
	 * @return Encrypted data that can be stored in insecure locations.
	 * @since 1.1.0
	 */
	KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, byte[] pepper, int vaultVersion);

	/**
	 * @return All key material of this cryptor
	 * @since 1.3.0
	 */
	byte[] getRawKey();

	@Override
	void destroy();

	/**
	 * Calls {@link #destroy()}.
	 */
	@Override
	void close();

}
