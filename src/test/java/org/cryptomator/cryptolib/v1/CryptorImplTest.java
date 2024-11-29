/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;

public class CryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	private PerpetualMasterkey masterkey;

	@BeforeEach
	public void setup() {
		this.masterkey = new PerpetualMasterkey(new byte[64]);
	}

	@Test
	public void testGetFileContentCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileContentCryptor(), CoreMatchers.instanceOf(FileContentCryptorImpl.class));
		}
	}

	@Test
	public void testGetFileHeaderCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileHeaderCryptor(), CoreMatchers.instanceOf(FileHeaderCryptorImpl.class));
		}
	}

	@Test
	public void testGetFileNameCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileNameCryptor(), CoreMatchers.instanceOf(FileNameCryptorImpl.class));
		}
	}

	@Test
	public void testExplicitDestruction() {
		PerpetualMasterkey masterkey = Mockito.mock(PerpetualMasterkey.class);
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			cryptor.destroy();
			Mockito.verify(masterkey).destroy();
			Mockito.when(masterkey.isDestroyed()).thenReturn(true);
			Assertions.assertTrue(cryptor.isDestroyed());
		}
	}

	@Test
	public void testImplicitDestruction() {
		PerpetualMasterkey masterkey = Mockito.mock(PerpetualMasterkey.class);
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertFalse(cryptor.isDestroyed());
		}
		Mockito.verify(masterkey).destroy();
	}

}
