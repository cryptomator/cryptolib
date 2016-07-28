/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.io.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.io.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.io.SeekableByteChannelMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FileContentEncryptorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;
	private static final SecretKey ENC_KEY = new SecretKeySpec(new byte[32], "AES");
	private static final SecretKey MAC_KEY = new SecretKeySpec(new byte[32], "HmacSHA256");

	private CryptorImpl cryptor;

	@Before
	public void setup() {
		cryptor = new CryptorImpl(ENC_KEY, MAC_KEY, RANDOM_MOCK);
	}

	@Test
	public void testDecryptEncrypted() throws IOException {
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assert.assertEquals(size, written);
		}

		ciphertextBuffer.position(0);

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, true)) {
			int read = ch.read(result);
			Assert.assertEquals(size, read);
		}

		Assert.assertArrayEquals(cleartext.array(), Arrays.copyOfRange(result.array(), 0, size));
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptManipulatedEncrypted() throws IOException {
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assert.assertEquals(size, written);
		}

		ciphertextBuffer.position(0);
		int firstByteOfFirstChunk = FileHeaderImpl.SIZE + 1; // not inside chunk MAC
		ciphertextBuffer.put(firstByteOfFirstChunk, (byte) ~ciphertextBuffer.get(firstByteOfFirstChunk));

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, true)) {
			ch.read(result);
		}
	}

	@Test
	public void testDecryptManipulatedEncryptedSkipAuth() throws InterruptedException, IOException {
		int size = 1 * 1024 * 1024;
		ByteBuffer ciphertextBuffer = ByteBuffer.allocate(2 * size);

		ByteBuffer cleartext = ByteBuffer.allocate(size);
		try (WritableByteChannel ch = new EncryptingWritableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor)) {
			int written = ch.write(cleartext);
			Assert.assertEquals(size, written);
		}

		ciphertextBuffer.position(0);
		int lastByteOfFirstChunk = FileHeaderImpl.SIZE + Constants.CHUNK_SIZE - 1; // inside chunk MAC
		ciphertextBuffer.put(lastByteOfFirstChunk, (byte) ~ciphertextBuffer.get(lastByteOfFirstChunk));

		ByteBuffer result = ByteBuffer.allocate(size + 1);
		try (ReadableByteChannel ch = new DecryptingReadableByteChannel(new SeekableByteChannelMock(ciphertextBuffer), cryptor, false)) {
			int read = ch.read(result);
			Assert.assertEquals(size, read);
		}

		Assert.assertArrayEquals(cleartext.array(), Arrays.copyOfRange(result.array(), 0, size));
	}

}
