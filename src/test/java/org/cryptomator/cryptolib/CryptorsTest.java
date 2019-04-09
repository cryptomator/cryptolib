/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.KeyFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

;

public class CryptorsTest {

	private final SecureRandom seeder = Mockito.mock(SecureRandom.class);

	@BeforeEach
	public void setup() {
		Mockito.when(seeder.generateSeed(Mockito.anyInt())).then(invocation -> {
				return new byte[(int) invocation.getArgument(0)];
		});
	}

	@Test
	public void testVersion1() {
		CryptorProvider cryptorProvider = Cryptors.version1(seeder);
		Assertions.assertNotNull(cryptorProvider);
		Cryptor cryptor = cryptorProvider.createNew();
		Assertions.assertNotNull(cryptor);
		FileContentCryptor fileContentCryptor = cryptor.fileContentCryptor();
		FileHeaderCryptor fileHeaderCryptor = cryptor.fileHeaderCryptor();
		FileNameCryptor fileNameCryptor = cryptor.fileNameCryptor();
		Assertions.assertNotNull(fileContentCryptor);
		Assertions.assertNotNull(fileHeaderCryptor);
		Assertions.assertNotNull(fileNameCryptor);
	}

	@Test
	public void testCleartextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Assertions.assertEquals(0l, Cryptors.cleartextSize(0l, c));
		Assertions.assertEquals(1l, Cryptors.cleartextSize(9l, c));
		Assertions.assertEquals(31l, Cryptors.cleartextSize(39l, c));
		Assertions.assertEquals(32l, Cryptors.cleartextSize(40l, c));
		Assertions.assertEquals(33l, Cryptors.cleartextSize(49l, c));
		Assertions.assertEquals(34l, Cryptors.cleartextSize(50l, c));
		Assertions.assertEquals(63l, Cryptors.cleartextSize(79l, c));
		Assertions.assertEquals(64l, Cryptors.cleartextSize(80l, c));
		Assertions.assertEquals(65l, Cryptors.cleartextSize(89l, c));
	}

	@Test
	public void testCleartextSizeWithNegativeCiphertextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			Cryptors.cleartextSize(-1, c);
		});
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
				Assertions.fail("Expected exception for input value " + val);
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

		Assertions.assertEquals(0l, Cryptors.ciphertextSize(0l, c));
		Assertions.assertEquals(9l, Cryptors.ciphertextSize(1l, c));
		Assertions.assertEquals(39l, Cryptors.ciphertextSize(31l, c));
		Assertions.assertEquals(40l, Cryptors.ciphertextSize(32l, c));
		Assertions.assertEquals(49l, Cryptors.ciphertextSize(33l, c));
		Assertions.assertEquals(50l, Cryptors.ciphertextSize(34l, c));
		Assertions.assertEquals(79l, Cryptors.ciphertextSize(63l, c));
		Assertions.assertEquals(80l, Cryptors.ciphertextSize(64l, c));
		Assertions.assertEquals(89l, Cryptors.ciphertextSize(65l, c));
	}

	@Test
	public void testCiphertextSizehNegativeCleartextSize() {
		Cryptor c = Mockito.mock(Cryptor.class);

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			Cryptors.ciphertextSize(-1, c);
		});
	}

	@Test
	public void testChangePassphrase() {
		CryptorProvider cryptorProvider = Cryptors.version1(seeder);
		Cryptor cryptor1 = cryptorProvider.createNew();
		byte[] origMasterkey = cryptor1.writeKeysToMasterkeyFile("password", 42).serialize();
		byte[] newMasterkey = Cryptors.changePassphrase(cryptorProvider, origMasterkey, "password", "betterPassw0rd!");
		Cryptor cryptor2 = cryptorProvider.createFromKeyFile(KeyFile.parse(newMasterkey), "betterPassw0rd!", 42);
		Assertions.assertNotNull(cryptor2);
	}

}
