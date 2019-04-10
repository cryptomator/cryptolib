/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class FileHeaderImplTest {

	@Test
	public void testConstructionFailsWithInvalidNonceSize() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new FileHeaderImpl(new byte[3], new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]);
		});
	}

	@Test
	public void testConstructionFailsWithInvalidKeySize() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], new byte[3]);
		});
	}

	@Test
	public void testDestruction() {
		byte[] nonNullKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
		Arrays.fill(nonNullKey, (byte) 0x42);
		FileHeaderImpl header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], nonNullKey);
		Assertions.assertFalse(header.isDestroyed());
		header.destroy();
		Assertions.assertTrue(header.isDestroyed());
		Assertions.assertArrayEquals(new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN], nonNullKey);
	}

}
