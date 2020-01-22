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
			new MessageDigestSupplier("FOO3000").get();
		});
	}

	@Test
	public void testGetSha1() {
		MessageDigest digest1 = MessageDigestSupplier.SHA1.get();
		Assertions.assertNotNull(digest1);

		MessageDigest digest2 = MessageDigestSupplier.SHA1.get();
		Assertions.assertSame(digest1, digest2);
	}

}
