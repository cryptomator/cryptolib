/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

public final class Cryptors {

	/**
	 * @param secureRandom E.g. an {@link ReseedingSecureRandom} instance.
	 * @return A version 1 CryptorProvider
	 */
	public static CryptorProvider version1(SecureRandom secureRandom) {
		return new org.cryptomator.cryptolib.v1.CryptorProviderImpl(secureRandom);
	}

}
