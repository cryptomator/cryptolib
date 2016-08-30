/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import java.lang.reflect.Method;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class MacSupplierTest {

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	@Test
	public void testConstructorWithInvalidDigest() {
		SecretKey key = new SecretKeySpec(new byte[16], "HmacSHA256");
		thrown.expect(IllegalArgumentException.class);
		new MacSupplier("FOO3000").withKey(key);
	}

	@Test
	public void testGetMac() throws InvalidKeyException, NoSuchAlgorithmException {
		SecretKey key = new SecretKeySpec(new byte[16], "HmacSHA256");
		Mac mac1 = MacSupplier.HMAC_SHA256.withKey(key);
		Assert.assertNotNull(mac1);

		Mac mac2 = MacSupplier.HMAC_SHA256.withKey(key);
		Assert.assertSame(mac1, mac2);
	}

	@Test
	public void testGetMacWithInvalidKey() throws InvalidKeyException, NoSuchAlgorithmException, ReflectiveOperationException {
		Key key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
		// invoked via reflection, as we can not cast Key to SecretKey.
		Method m = MacSupplier.class.getMethod("withKey", SecretKey.class);
		thrown.expect(IllegalArgumentException.class);
		m.invoke(MacSupplier.HMAC_SHA256, key);
	}

}
