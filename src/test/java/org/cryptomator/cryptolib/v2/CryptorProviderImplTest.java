/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;

public class CryptorProviderImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	private CryptorProviderImpl cryptorProvider;

	@BeforeEach
	public void setup() {
		cryptorProvider = new CryptorProviderImpl(RANDOM_MOCK);
	}

	@Test
	public void testWithKey() {
		Masterkey masterkey = Mockito.mock(Masterkey.class);
		CryptorImpl cryptor = cryptorProvider.withKey(masterkey);
		Assertions.assertNotNull(cryptor);
	}

}
