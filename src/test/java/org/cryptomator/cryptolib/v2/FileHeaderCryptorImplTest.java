/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final SecureRandom ANTI_REUSE_PRNG = SecureRandomMock.cycle((byte) 0x13, (byte) 0x37);

	private FileHeaderCryptorImpl headerCryptor;

	@Before
	public void setup() {
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		headerCryptor = new FileHeaderCryptorImpl(encKey, RANDOM_MOCK);

		// init cipher with distinct IV to avoid cipher-internal anti-reuse checking
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		ANTI_REUSE_PRNG.nextBytes(nonce);
		CipherSupplier.AES_GCM.forEncryption(encKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
	}

	@Test
	public void testEncryption() {
		// set nonce to: AAAAAAAAAAAAAAAA
		// set payload to: //////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
		FileHeader header = new FileHeaderImpl(new byte[12], new byte[32]);
		// encrypt payload:
		// echo -n "//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 --decode \
		// | openssl enc -aes-256-gcm -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 -a
		// -> MVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhew==

		// the following string contains nonce + ciphertext + tag. The tag is not produced by openssl, though.
		final String expected = "AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjU0=";

		ByteBuffer result = headerCryptor.encryptHeader(header);

		Assert.assertArrayEquals(BaseEncoding.base64().decode(expected), result.array());
	}

	@Test
	public void testHeaderSize() {
		Assert.assertEquals(org.cryptomator.cryptolib.v2.FileHeaderImpl.SIZE, headerCryptor.headerSize());
		Assert.assertEquals(org.cryptomator.cryptolib.v2.FileHeaderImpl.SIZE, headerCryptor.encryptHeader(headerCryptor.create()).limit());
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testDecryption() {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjU0=");
		FileHeader header = headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		Assert.assertEquals(header.getFilesize(), -1l);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDecryptionWithTooShortHeader() {
		byte[] ciphertext = new byte[7];
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptionWithInvalidTag1() {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUA=");
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

	@Test(expected = AuthenticationFailedException.class)
	public void testDecryptionWithInvalidTag2() {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUa=");
		headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
	}

}
