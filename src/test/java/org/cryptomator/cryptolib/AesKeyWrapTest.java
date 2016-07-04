/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class AesKeyWrapTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void wrapAndUnwrap() throws InvalidKeyException, NoSuchAlgorithmException {
		SecretKey kek = new SecretKeySpec(new byte[32], "AES");
		SecretKey key = new SecretKeySpec(new byte[32], "AES");
		byte[] wrapped = AesKeyWrap.wrap(kek, key);
		SecretKey unwrapped = AesKeyWrap.unwrap(kek, wrapped, "AES");
		Assert.assertEquals(key, unwrapped);
	}

	@Test
	public void wrapWithInvalidKey() {
		SecretKey kek = new SecretKeySpec(new byte[32], "AES");
		SecretKey key = new SecretKeySpec(new byte[17], "AES");
		thrown.expect(IllegalArgumentException.class);
		AesKeyWrap.wrap(kek, key);
	}

}
