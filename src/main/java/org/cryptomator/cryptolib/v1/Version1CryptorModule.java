/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptoLibVersion;
import org.cryptomator.cryptolib.api.CryptoLibVersion.Version;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.common.SecureRandomModule;
import org.cryptomator.cryptolib.common.SecureRandomModule.FastSecureRandom;

import dagger.Module;
import dagger.Provides;

@Module(includes = {SecureRandomModule.class})
public class Version1CryptorModule {

	@Provides
	@CryptoLibVersion(Version.ONE)
	public CryptorProvider provideCryptorProvider(@FastSecureRandom SecureRandom secureRandom) {
		return new CryptorProviderImpl(secureRandom);
	}

}
