/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

public class FileContentChunksTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Test
	public void testMacIsValidAfterEncryption() throws NoSuchAlgorithmException {
		SecretKey encryptionKey = new SecretKeySpec(new byte[16], "AES");
		SecretKey macKey = new SecretKeySpec(new byte[16], "HmacSHA256");

		ByteBuffer result = FileContentChunks.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[16], encryptionKey, macKey, RANDOM_MOCK);
		Assert.assertTrue(FileContentChunks.checkChunkMac(macKey, new byte[16], 42l, result));
		Assert.assertFalse(FileContentChunks.checkChunkMac(macKey, new byte[16], 43l, result));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws NoSuchAlgorithmException {
		SecretKey encryptionKey = new SecretKeySpec(new byte[16], "AES");
		SecretKey macKey = new SecretKeySpec(new byte[16], "HmacSHA256");

		ByteBuffer ciphertext = FileContentChunks.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[16], encryptionKey, macKey, RANDOM_MOCK);
		ByteBuffer result = FileContentChunks.decryptChunk(ciphertext, encryptionKey);
		Assert.assertArrayEquals("asd".getBytes(), result.array());
	}

}
