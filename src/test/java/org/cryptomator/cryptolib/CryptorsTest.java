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
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collection;

public class CryptorsTest {

	@ParameterizedTest(name = "cleartextSize({1}) == {0}")
	@CsvSource(value = {
			"0,0",
			"1,9",
			"31,39",
			"32,40",
			"33,49",
			"34,50",
			"63,79",
			"64,80",
			"65,89"
	})
	public void testCleartextSize(int cleartextSize, int ciphertextSize) {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Assertions.assertEquals(cleartextSize, Cryptors.cleartextSize(ciphertextSize, c));
	}

	@ParameterizedTest(name = "cleartextSize({0}) == undefined")
	@ValueSource(ints = {-1, 1, 8, 41, 48, 81, 88})
	public void testCleartextSizeWithInvalidCiphertextSize(int invalidCiphertextSize) {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);
		
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			Cryptors.cleartextSize(invalidCiphertextSize, c);
		});
	}

	@ParameterizedTest(name = "ciphertextSize({0}) == {1}")
	@CsvSource(value = {
			"0,0",
			"1,9",
			"31,39",
			"32,40",
			"33,49",
			"34,50",
			"63,79",
			"64,80",
			"65,89"
	})
	public void testCiphertextSize(int cleartextSize, int ciphertextSize) {
		Cryptor c = Mockito.mock(Cryptor.class);
		FileContentCryptor cc = Mockito.mock(FileContentCryptor.class);
		Mockito.when(c.fileContentCryptor()).thenReturn(cc);
		Mockito.when(cc.cleartextChunkSize()).thenReturn(32);
		Mockito.when(cc.ciphertextChunkSize()).thenReturn(40);

		Assertions.assertEquals(ciphertextSize, Cryptors.ciphertextSize(cleartextSize, c));
	}

	@ParameterizedTest(name = "ciphertextSize({0}) == undefined")
	@ValueSource(ints = {-1})
	public void testCiphertextSizewithInvalidCleartextSize(int invalidCleartextSize) {
		Cryptor c = Mockito.mock(Cryptor.class);

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			Cryptors.ciphertextSize(invalidCleartextSize, c);
		});
	}

}
