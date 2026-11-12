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

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

class MacSupplierTest {

	@Test
	void testConstructorWithInvalidDigest() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new MacSupplier("FOO3000");
		});
	}

	@Test
	void testGetMac() {
		SecretKey key = new SecretKeySpec(new byte[16], "HmacSHA256");
		Mac mac1 = MacSupplier.HMAC_SHA256.keyed(key);
		Mac mac2 = MacSupplier.HMAC_SHA256.keyed(key);
		Assertions.assertNotNull(mac1);
		Assertions.assertNotSame(mac1, mac2);
	}

	@Test
	void testGetMacWithInvalidKey() throws NoSuchAlgorithmException, ReflectiveOperationException {
		Key key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
		// invoked via reflection, as we can not cast Key to SecretKey.
		Method m = MacSupplier.class.getMethod("keyed", SecretKey.class);
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			m.invoke(MacSupplier.HMAC_SHA256, key);
		});
	}

}
