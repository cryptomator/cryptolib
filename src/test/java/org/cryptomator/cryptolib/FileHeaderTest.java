/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.util.Arrays;

import org.junit.Assert;
import org.junit.Test;

public class FileHeaderTest {

	@Test(expected = IllegalArgumentException.class)
	public void testConstructionFailsWithInvalidNonceSize() {
		new FileHeader(new byte[3], new byte[FileHeader.Payload.CONTENT_KEY_LEN]);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testConstructionFailsWithInvalidKeySize() {
		new FileHeader(new byte[FileHeader.NONCE_LEN], new byte[3]);
	}

	@Test
	public void testDestruction() {
		byte[] nonNullKey = new byte[FileHeader.Payload.CONTENT_KEY_LEN];
		Arrays.fill(nonNullKey, (byte) 0x42);
		FileHeader header = new FileHeader(new byte[FileHeader.NONCE_LEN], nonNullKey);
		Assert.assertFalse(header.isDestroyed());
		header.destroy();
		Assert.assertTrue(header.isDestroyed());
		Assert.assertArrayEquals(new byte[FileHeader.Payload.CONTENT_KEY_LEN], nonNullKey);
	}

}
