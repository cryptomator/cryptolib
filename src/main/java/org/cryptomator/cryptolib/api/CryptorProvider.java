/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import java.security.SecureRandom;
import java.util.ServiceLoader;

public interface CryptorProvider {

	/**
	 * A combination of ciphers to use for filename and file content encryption
	 */
	enum Scheme {
		/**
		 * AES-SIV for file name encryption
		 * AES-CTR + HMAC for content encryption
		 */
		SIV_CTRMAC,

		/**
		 * AES-SIV for file name encryption
		 * AES-GCM for content encryption
		 */
		SIV_GCM,

		/**
		 * Experimental implementation of UVF draft
		 * @deprecated may be removed any time
		 * @see <a href="https://github.com/encryption-alliance/unified-vault-format">UVF</a>
		 */
		@Deprecated
		UVF_DRAFT,
	}

	/**
	 * Finds a CryptorProvider implementation for the given combination of ciphers.
	 *
	 * @param scheme A cipher combination
	 * @return A CryptorProvider implementation supporting the requestes <code>scheme</code>
	 * @throws UnsupportedOperationException If the <code>scheme</code> is not implemented
	 */
	static CryptorProvider forScheme(Scheme scheme) {
		for (CryptorProvider provider : ServiceLoader.load(CryptorProvider.class)) {
			if (provider.scheme().equals(scheme)) {
				return provider;
			}
		}
		throw new UnsupportedOperationException("Scheme not supported: " + scheme.name());
	}

	/**
	 * @return The combination of ciphers used by this CryptorProvider implementation.
	 */
	Scheme scheme();

	/**
	 * Creates a new Cryptor instance for the given key
	 *
	 * @param masterkey The key used by the returned cryptor during encryption and decryption
	 * @param random    A native (if possible) SecureRandom used to seed internal CSPRNGs
	 * @return A new cryptor
	 */
	Cryptor provide(Masterkey masterkey, SecureRandom random);

}
