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

import java.security.MessageDigest;

public class MessageDigestSupplierTest {

	@Test
	public void testConstructorWithInvalidDigest() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new MessageDigestSupplier("FOO3000");
		});
	}

	@Test
	public void testGetSha1() {
		try (ObjectPool.Lease<MessageDigest> digest = MessageDigestSupplier.SHA1.instance()) {
			Assertions.assertNotNull(digest);
		}

		try (ObjectPool.Lease<MessageDigest> digest = MessageDigestSupplier.SHA1.instance()) {
			Assertions.assertNotNull(digest);
		}
	}

}
