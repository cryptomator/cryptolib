/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;

public class AesKeyWrapTest {

	@Test
	public void wrapAndUnwrap() throws InvalidKeyException {
		SecretKey kek = new SecretKeySpec(new byte[32], "AES");
		SecretKey key = new SecretKeySpec(new byte[32], "AES");
		byte[] wrapped = AesKeyWrap.wrap(kek, key);
		SecretKey unwrapped = AesKeyWrap.unwrap(kek, wrapped, "AES");
		Assertions.assertEquals(key, unwrapped);
	}

	@Test
	public void wrapWithInvalidKey() {
		SecretKey kek = new SecretKeySpec(new byte[32], "AES");
		SecretKey key = new SecretKeySpec(new byte[17], "AES");
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			AesKeyWrap.wrap(kek, key);
		});
	}

	@Test
	public void unwrapWithInvalidKey() {
		SecretKey kek = new SecretKeySpec(new byte[32], "AES");
		SecretKey key = new SecretKeySpec(new byte[32], "AES");
		byte[] wrapped = AesKeyWrap.wrap(kek, key);
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			AesKeyWrap.unwrap(kek, wrapped, "FOO", Cipher.PRIVATE_KEY);
		});
	}

}
