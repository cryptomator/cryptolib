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
	public Cryptor createNew();

	/**
	 * @param keyFile The parsed key file
	 * @param passphrase The passphrase to use for decrypting the keyfile
	 * @param expectedVaultVersion The vault version expected in this file
	 * @return A new Cryptor instance using the keys from the supplied keyfile
	 * @throws UnsupportedVaultFormatException If the vault has been created with a different version than <code>expectedVaultVersion</code>
	 * @throws InvalidPassphraseException If the key derived from the passphrase could not be used to decrypt the keyfile.
	 */
	public Cryptor createFromKeyFile(KeyFile keyFile, CharSequence passphrase, int expectedVaultVersion) throws UnsupportedVaultFormatException, InvalidPassphraseException;

}
