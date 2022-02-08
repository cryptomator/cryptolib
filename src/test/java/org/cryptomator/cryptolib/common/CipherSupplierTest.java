/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import java.security.spec.AlgorithmParameterSpec;

public class CipherSupplierTest {

	@Test
	public void testGetUnknownCipher() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new CipherSupplier("doesNotExist");
		});
	}

	@Test
	public void testGetCipherWithInvalidKey() {
		CipherSupplier supplier = new CipherSupplier("AES/CBC/PKCS5Padding");
		SecretKey key = new DestroyableSecretKey(new byte[13], "AES");
		AlgorithmParameterSpec params = new IvParameterSpec(new byte[16]);
		IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			supplier.encryptionCipher(key, params);
		});
		MatcherAssert.assertThat(exception.getMessage(), CoreMatchers.containsString("Invalid key"));
	}

	@Test
	public void testGetCipherWithInvalidAlgorithmParam() {
		CipherSupplier supplier = new CipherSupplier("AES/CBC/PKCS5Padding");
		SecretKey key = new DestroyableSecretKey(new byte[16], "AES");
		AlgorithmParameterSpec params = new RC5ParameterSpec(1, 1, 8);
		IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			supplier.encryptionCipher(key, params);
		});
		MatcherAssert.assertThat(exception.getMessage(), CoreMatchers.containsString("Algorithm parameter not appropriate for"));
	}

}
