/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final SecureRandom ANTI_REUSE_PRNG = SecureRandomMock.PRNG_RANDOM;

	private FileHeaderCryptorImpl headerCryptor;

	@BeforeEach
	public void setup() {
		DestroyableSecretKey encKey = new DestroyableSecretKey(new byte[32], "AES");
		headerCryptor = new FileHeaderCryptorImpl(encKey, RANDOM_MOCK);

		// create new (unused) cipher, just to cipher.init() internally. This is an attempt to avoid
		// InvalidAlgorithmParameterExceptions due to IV-reuse, when the actual unit tests use constant IVs
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		ANTI_REUSE_PRNG.nextBytes(nonce);
		Cipher cipher = CipherSupplier.AES_GCM.forEncryption(encKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
		Assertions.assertNotNull(cipher);
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

		Assertions.assertArrayEquals(BaseEncoding.base64().decode(expected), result.array());
	}

	@Test
	public void testHeaderSize() {
		Assertions.assertEquals(org.cryptomator.cryptolib.v2.FileHeaderImpl.SIZE, headerCryptor.headerSize());
		Assertions.assertEquals(org.cryptomator.cryptolib.v2.FileHeaderImpl.SIZE, headerCryptor.encryptHeader(headerCryptor.create()).limit());
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testDecryption() throws AuthenticationFailedException {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjU0=");
		FileHeader header = headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		Assertions.assertEquals(header.getFilesize(), -1l);
	}

	@Test
	public void testDecryptionWithTooShortHeader() {
		byte[] ciphertext = new byte[7];
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		});
	}

	@Test
	public void testDecryptionWithInvalidTag1() {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUA=");
		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		});
	}

	@Test
	public void testDecryptionWithInvalidTag2() {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUa=");
		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		});
	}

}
