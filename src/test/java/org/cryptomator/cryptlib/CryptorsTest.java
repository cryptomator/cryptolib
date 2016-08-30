/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptlib;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

import org.cryptomator.cryptolib.Cryptors;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;

public class CryptorsTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void testVersion1() {
		SecureRandom secRandom = Mockito.mock(SecureRandom.class);
		Assert.assertTrue(Cryptors.version1(secRandom) instanceof org.cryptomator.cryptolib.v1.CryptorProviderImpl);
	}

	@Test
	public void testCleartextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Assert.assertEquals(0l, Cryptors.cleartextSize(0l, c));
		Assert.assertEquals(1l, Cryptors.cleartextSize(9l, c));
		Assert.assertEquals(31l, Cryptors.cleartextSize(39l, c));
		Assert.assertEquals(32l, Cryptors.cleartextSize(40l, c));
		Assert.assertEquals(33l, Cryptors.cleartextSize(49l, c));
		Assert.assertEquals(34l, Cryptors.cleartextSize(50l, c));
		Assert.assertEquals(63l, Cryptors.cleartextSize(79l, c));
		Assert.assertEquals(64l, Cryptors.cleartextSize(80l, c));
		Assert.assertEquals(65l, Cryptors.cleartextSize(89l, c));
	}

	@Test
	public void testCleartextSizeWithInvalidCiphertextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Collection<Integer> undefinedValues = Arrays.asList(1, 8, 41, 48, 81, 88);
		for (Integer val : undefinedValues) {
			try {
				Cryptors.cleartextSize(val, c);
				Assert.fail("Expected exception for input value " + val);
			} catch (IllegalArgumentException e) {
				continue;
			}
		}
	}

	@Test
	public void testCiphertextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Assert.assertEquals(0l, Cryptors.ciphertextSize(0l, c));
		Assert.assertEquals(9l, Cryptors.ciphertextSize(1l, c));
		Assert.assertEquals(39l, Cryptors.ciphertextSize(31l, c));
		Assert.assertEquals(40l, Cryptors.ciphertextSize(32l, c));
		Assert.assertEquals(49l, Cryptors.ciphertextSize(33l, c));
		Assert.assertEquals(50l, Cryptors.ciphertextSize(34l, c));
		Assert.assertEquals(79l, Cryptors.ciphertextSize(63l, c));
		Assert.assertEquals(80l, Cryptors.ciphertextSize(64l, c));
		Assert.assertEquals(89l, Cryptors.ciphertextSize(65l, c));
	}

}
