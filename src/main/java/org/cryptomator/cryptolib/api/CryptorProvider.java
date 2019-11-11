/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

public interface CryptorProvider {

	/**
	 * @return A new Cryptor instance using randomized keys
	 */
	Cryptor createNew();

	/**
	 * @param rawKey The key to use for the new cryptor
	 * @return A new Cryptor instance using the given key
	 * @throws IllegalArgumentException if the key is of invalid length
	 * @since 1.3.0
	 */
	Cryptor createFromRawKey(byte[] rawKey) throws IllegalArgumentException;

	/**
	 * Shortcut for {@link #createFromKeyFile(KeyFile, CharSequence, byte[], int)} with en empty pepper.
	 * 
	 * @param keyFile The parsed key file
	 * @param passphrase The passphrase to use for decrypting the keyfile
	 * @param expectedVaultVersion The vault version expected in this file
	 * @return A new Cryptor instance using the keys from the supplied keyfile
	 * @throws UnsupportedVaultFormatException If the vault has been created with a different version than <code>expectedVaultVersion</code>
	 * @throws InvalidPassphraseException If the key derived from the passphrase could not be used to decrypt the keyfile.
	 * @see #createFromKeyFile(KeyFile, CharSequence, byte[], int)
	 */
	Cryptor createFromKeyFile(KeyFile keyFile, CharSequence passphrase, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException;

	/**
	 * @param keyFile The parsed key file
	 * @param passphrase The passphrase to use for decrypting the keyfile
	 * @param pepper An application-specific pepper added to the salt during key-derivation (if applicable)
	 * @param expectedVaultVersion The vault version expected in this file
	 * @return A new Cryptor instance using the keys from the supplied keyfile
	 * @throws UnsupportedVaultFormatException If the vault has been created with a different version than <code>expectedVaultVersion</code>
	 * @throws InvalidPassphraseException If the key derived from the passphrase and pepper could not be used to decrypt the keyfile.
	 * @since 1.1.0
	 */
	Cryptor createFromKeyFile(KeyFile keyFile, CharSequence passphrase, byte[] pepper, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException;

}
