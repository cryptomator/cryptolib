/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

import java.security.SecureRandom;

public class CryptorProviderImpl implements CryptorProvider {

	@Override
	public Scheme scheme() {
		return Scheme.UVF_DRAFT;
	}

	@Override
	public CryptorImpl provide(Masterkey masterkey, SecureRandom random) {
		return new CryptorImpl(masterkey, ReseedingSecureRandom.create(random));
	}

}
