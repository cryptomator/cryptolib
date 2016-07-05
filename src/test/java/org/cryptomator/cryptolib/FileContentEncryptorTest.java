/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.Channels;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class FileContentEncryptorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;

	private SecretKey macKey;
	private FileHeader header;

	@Before
	public void setup() {
		macKey = new SecretKeySpec(new byte[16], "HmacSHA256");
		header = new FileHeader(new byte[16], new byte[32]);
	}

	@Test
	public void testDecryptEncrypted() throws InterruptedException, IOException {
		// 2mb
		byte[] cleartext = new byte[20 * 1024 * 1024];

		ByteArrayInputStream cleartextIn = new ByteArrayInputStream(cleartext);
		ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
		new FileContentEncryptor(header, macKey, RANDOM_MOCK).encrypt(Channels.newChannel(cleartextIn), Channels.newChannel(ciphertextOut), 0);
		byte[] ciphertext = ciphertextOut.toByteArray();

		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		ByteArrayOutputStream cleartextOut = new ByteArrayOutputStream();
		new FileContentDecryptor(header, macKey, true).decrypt(Channels.newChannel(ciphertextIn), Channels.newChannel(cleartextOut), 0);

		Assert.assertArrayEquals(cleartext, cleartextOut.toByteArray());
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptManipulatedEncrypted() throws InterruptedException, IOException {
		// 2mb
		byte[] cleartext = new byte[20 * 1024 * 1024];

		ByteArrayInputStream cleartextIn = new ByteArrayInputStream(cleartext);
		ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
		new FileContentEncryptor(header, macKey, RANDOM_MOCK).encrypt(Channels.newChannel(cleartextIn), Channels.newChannel(ciphertextOut), 0);
		byte[] ciphertext = ciphertextOut.toByteArray();
		ciphertext[ciphertext.length - 1] = (byte) ~ciphertext[ciphertext.length - 1];

		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		ByteArrayOutputStream cleartextOut = new ByteArrayOutputStream();
		new FileContentDecryptor(header, macKey, true).decrypt(Channels.newChannel(ciphertextIn), Channels.newChannel(cleartextOut), 0);
	}

	@Test
	public void testDecryptManipulatedEncryptedSkipAuth() throws InterruptedException, IOException {
		// 2mb
		byte[] cleartext = new byte[20 * 1024 * 1024];

		ByteArrayInputStream cleartextIn = new ByteArrayInputStream(cleartext);
		ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
		new FileContentEncryptor(header, macKey, RANDOM_MOCK).encrypt(Channels.newChannel(cleartextIn), Channels.newChannel(ciphertextOut), 0);
		byte[] ciphertext = ciphertextOut.toByteArray();
		ciphertext[ciphertext.length - 1] = (byte) ~ciphertext[ciphertext.length - 1];

		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		ByteArrayOutputStream cleartextOut = new ByteArrayOutputStream();
		new FileContentDecryptor(header, macKey, false).decrypt(Channels.newChannel(ciphertextIn), Channels.newChannel(cleartextOut), 0);

		Assert.assertArrayEquals(cleartext, cleartextOut.toByteArray());
	}

}
