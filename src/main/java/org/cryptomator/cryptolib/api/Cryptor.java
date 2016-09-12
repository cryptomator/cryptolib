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

public interface Cryptor extends Destroyable {

	public FileContentCryptor fileContentCryptor();

	public FileHeaderCryptor fileHeaderCryptor();

	public FileNameCryptor fileNameCryptor();

	/**
	 * @param passphrase The passphrase used to encrypt the key material.
	 * @param vaultVersion Will be checked upon decryption of this masterkey.
	 * @return Encrypted data that can be stored in insecure locations.
	 */
	public KeyFile writeKeysToMasterkeyFile(CharSequence passphrase, int vaultVersion);

	@Override
	void destroy();

}
