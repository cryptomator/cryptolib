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
import org.junit.BeforeClass;
import org.junit.Test;

public class FileContentAuthenticatorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.PRNG_RANDOM;

	private static SecretKey MAC_KEY;
	private static FileHeader HEADER;
	private static byte[] AUTHENTIC_CIPHERTEXT;

	private byte[] ciphertext;

	@BeforeClass
	public static void setupClass() throws IOException {
		MAC_KEY = new SecretKeySpec(new byte[16], "HmacSHA256");
		HEADER = FileHeaders.create(SecureRandomMock.NULL_RANDOM);

		ByteArrayInputStream cleartextIn = new ByteArrayInputStream(new byte[20 * 1024 * 1024]);
		ByteArrayOutputStream ciphertextOut = new ByteArrayOutputStream();
		new FileContentEncryptor(HEADER, MAC_KEY, RANDOM_MOCK).encrypt(Channels.newChannel(cleartextIn), Channels.newChannel(ciphertextOut), 0);
		AUTHENTIC_CIPHERTEXT = ciphertextOut.toByteArray();
	}

	@Before
	public void setup() throws IOException {
		ciphertext = new byte[AUTHENTIC_CIPHERTEXT.length];
		System.arraycopy(AUTHENTIC_CIPHERTEXT, 0, ciphertext, 0, AUTHENTIC_CIPHERTEXT.length);
	}

	@Test
	public void testAuthentic() throws InterruptedException, IOException {
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertTrue(authentic);
	}

	@Test
	public void testUnauthenticNonce() throws InterruptedException, IOException {
		int pos = 0;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

	@Test
	public void testUnauthenticContent() throws InterruptedException, IOException {
		int pos = Constants.NONCE_SIZE;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

	@Test
	public void testUnauthenticMac() throws InterruptedException, IOException {
		int pos = Constants.NONCE_SIZE + Constants.PAYLOAD_SIZE;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

	@Test
	public void testUnauthenticNonce2() throws InterruptedException, IOException {
		int pos = 20 * Constants.CHUNK_SIZE;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

	@Test
	public void testUnauthenticContent2() throws InterruptedException, IOException {
		int pos = 20 * Constants.CHUNK_SIZE + Constants.NONCE_SIZE;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

	@Test
	public void testUnauthenticMac2() throws InterruptedException, IOException {
		int pos = 20 * Constants.CHUNK_SIZE + Constants.NONCE_SIZE + Constants.PAYLOAD_SIZE;
		ciphertext[pos] = (byte) ~ciphertext[pos];
		ByteArrayInputStream ciphertextIn = new ByteArrayInputStream(ciphertext);
		boolean authentic = new FileContentAuthenticator(HEADER, MAC_KEY).authenticate(Channels.newChannel(ciphertextIn), 0);
		Assert.assertFalse(authentic);
	}

}
