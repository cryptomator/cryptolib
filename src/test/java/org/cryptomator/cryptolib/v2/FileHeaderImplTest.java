/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class FileHeaderImplTest {

	@Test
	public void testConstructionFailsWithInvalidNonceSize() {
		FileHeaderImpl.Payload payload = new FileHeaderImpl.Payload(-1, new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]);
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new FileHeaderImpl(new byte[3], payload);
		});
	}

	@Test
	public void testConstructionFailsWithInvalidKeySize() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new FileHeaderImpl.Payload(-1, new byte[3]);
		});
	}

	@Test
	public void testDestruction() {
		byte[] nonNullKey = new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN];
		Arrays.fill(nonNullKey, (byte) 0x42);
		FileHeaderImpl.Payload payload = new FileHeaderImpl.Payload(-1, nonNullKey);
		FileHeaderImpl header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], payload);
		Assertions.assertFalse(header.isDestroyed());
		header.destroy();
		Assertions.assertTrue(header.isDestroyed());
		Assertions.assertTrue(payload.isDestroyed());
		Assertions.assertTrue(payload.getContentKey().isDestroyed());
	}

}
