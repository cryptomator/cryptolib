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
import java.security.SecureRandom;

import javax.crypto.AEADBadTagException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.spongycastle.util.encoders.Base64;

public class FileHeaderCryptorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private FileHeaderCryptor headerCryptor;

	@Before
	public void setup() {
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		SecretKey macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
		headerCryptor = new FileHeaderCryptor(encKey, macKey, RANDOM_MOCK);
	}

	@Test
	public void testEncryption() {
		// set nonce to: AAAAAAAAAAAAAAAAAAAAAAAA
		// set payload to: AAAAAAAAACoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
		FileHeader header = headerCryptor.create();
		header.getPayload().setFilesize(42l);
		// encrypt payload:
		// echo -n "AAAAAAAAACoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 --decode | openssl enc -aes-256-ctr -K 0000000000000000000000000000000000000000000000000000000000000000 -iv
		// -> 3JXAeKJAiaOtSKIUkoQgh1MPivvHRTa5qWO08cTLc4vOp0A9TWBrbg==

		// mac nonce + encrypted payload:
		// (openssl dgst -sha256 -mac HMAC -macopt hexkey:0000000000000000000000000000000000000000000000000000000000000000 -binary)

		// concat nonce + encrypted payload + mac:
		final String expected = "AAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJA==";

		ByteBuffer result = headerCryptor.encryptHeader(header);

		Assert.assertArrayEquals(Base64.decode(expected), result.array());
	}

	@Test
	public void testDecryption() throws AEADBadTagException {
		byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJA==");
		FileHeader header = headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		Assert.assertEquals(header.getPayload().getFilesize(), 42l);
	}

	@Test(expected = IllegalStateException.class)
	public void testDecryptionWithTooShortHeader() throws AEADBadTagException {
		byte[] ciphertext = new byte[7];
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptionWithInvalidMac1() throws AEADBadTagException {
		byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJa==");
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptionWithInvalidMac2() throws AEADBadTagException {
		byte[] ciphertext = Base64.decode("aAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJA==");
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

}
