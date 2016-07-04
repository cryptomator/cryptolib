/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.RC5ParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CipherSupplierTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test(expected = IllegalArgumentException.class)
	public void testGetUnknownCipher() {
		new CipherSupplier("doesNotExist");
	}

	@Test
	public void testGetCipherWithInvalidKey() {
		CipherSupplier supplier = new CipherSupplier("AES/CBC/PKCS5Padding");
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("Invalid key");
		supplier.forMode(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[13], "AES"), new IvParameterSpec(new byte[16]));
	}

	@Test
	public void testGetCipherWithInvalidAlgorithmParam() {
		CipherSupplier supplier = new CipherSupplier("AES/CBC/PKCS5Padding");
		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("Algorithm parameter not appropriate for");
		supplier.forMode(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[16], "AES"), new RC5ParameterSpec(1, 1, 8));
	}

}
