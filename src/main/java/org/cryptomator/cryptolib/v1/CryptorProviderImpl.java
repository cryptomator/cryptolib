/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;

import java.security.SecureRandom;

public class CryptorProviderImpl implements CryptorProvider {

	private final SecureRandom random;

	public CryptorProviderImpl(SecureRandom random) {
		this.random = random;
	}

	@Override
	public CryptorImpl withKey(Masterkey masterkey) {
		return new CryptorImpl(masterkey, random);
	}

}
