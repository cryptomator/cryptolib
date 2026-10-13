/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;

public class CryptorProviderImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Test
	public void testProvide() {
		CvfMasterkey masterkey = Mockito.mock(CvfMasterkey.class);
		CryptorImpl cryptor = new CryptorProviderImpl().provide(masterkey, RANDOM_MOCK);
		Assertions.assertNotNull(cryptor);
	}

}
