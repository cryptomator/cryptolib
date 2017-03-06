/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;

import org.cryptomator.cryptolib.api.CryptoLibVersion;
import org.cryptomator.cryptolib.api.CryptoLibVersion.Version;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.common.SecureRandomModule;
import org.cryptomator.cryptolib.common.SecureRandomModule.FastSecureRandom;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import dagger.Module;
import dagger.Provides;

@Module(includes = {SecureRandomModule.class})
public class Version1CryptorModule {

	private static final Logger LOG = LoggerFactory.getLogger(Version1CryptorModule.class);

	@Provides
	@CryptoLibVersion(Version.ONE)
	public CryptorProvider provideCryptorProvider(@FastSecureRandom SecureRandom secureRandom) {
		assertRequiredKeyLengthIsAllowed();
		return new CryptorProviderImpl(secureRandom);
	}

	private void assertRequiredKeyLengthIsAllowed() {
		if (!isRequiredKeyLengthAllowed()) {
			LOG.error("Required key length not supported. See https://github.com/cryptomator/cryptolib/wiki/Restricted-Key-Size.");
			throw new IllegalStateException("Required key length not supported.");
		}
	}

	// visible for testing
	boolean isRequiredKeyLengthAllowed() {
		try {
			int requiredKeyLengthBits = Constants.KEY_LEN_BYTES * Byte.SIZE;
			int allowedKeyLengthBits = Cipher.getMaxAllowedKeyLength(Constants.ENC_ALG);
			return allowedKeyLengthBits >= requiredKeyLengthBits;
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Hard-coded algorithm \"" + Constants.ENC_ALG + "\" not supported.", e);
		}
	}

}
