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
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	private FileHeaderCryptorImpl headerCryptor;

	@BeforeEach
	public void setup() {
		PerpetualMasterkey masterkey = new PerpetualMasterkey(new byte[64]);
		headerCryptor = new FileHeaderCryptorImpl(masterkey, RANDOM_MOCK);

		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
				cipher.get();
			}
		});
	}

	@Test
	public void testEncryption() {
		// set nonce to: AAAAAAAAAAAAAAAA
		// set payload to: //////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
		FileHeaderImpl.Payload payload = new FileHeaderImpl.Payload(-1, new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]);
		FileHeader header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], payload);
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
		Assertions.assertEquals(header.getReserved(), -1l);
	}

	@Test
	public void testDecryptionWithTooShortHeader() {
		ByteBuffer ciphertext = ByteBuffer.allocate(7);

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidTag1() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUA="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidTag2() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAMVi/wrKflJEHTsXTuvOdGHJgA8o3pip00aL1jnUGNY7dSrEoTUrhey+maVG6P0F2RBmZR74SjUa="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

}
