/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private FileHeaderCryptorImpl headerCryptor;

	@BeforeEach
	public void setup() {
		Masterkey masterkey = new Masterkey(new byte[64]);
		headerCryptor = new FileHeaderCryptorImpl(masterkey, RANDOM_MOCK);
	}

	@Test
	public void testEncryption() {
		// set nonce to: AAAAAAAAAAAAAAAAAAAAAA==
		// set payload to: //////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==
		FileHeaderImpl.Payload payload = new FileHeaderImpl.Payload(-1, new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]);
		FileHeader header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], payload);
		// encrypt payload:
		// echo -n "//////////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==" | base64 --decode \
		// | openssl enc -aes-256-ctr -K 0000000000000000000000000000000000000000000000000000000000000000 -iv 00000000000000000000000000000000 | base64
		// -> I2o/h12/dnatSKIUkoQgh1MPivvHRTa5qWO08cTLc4vOp0A9TWBrbg==

		// mac nonce + encrypted payload:
		// (openssl dgst -sha256 -mac HMAC -macopt hexkey:0000000000000000000000000000000000000000000000000000000000000000 -binary)

		// concat nonce + encrypted payload + mac:
		final String expected = "AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfMdzvHF3f9EE0LSnRLSsu6ps3IRcJg==";

		ByteBuffer result = headerCryptor.encryptHeader(header);

		Assertions.assertArrayEquals(BaseEncoding.base64().decode(expected), result.array());
	}

	@Test
	public void testHeaderSize() {
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.headerSize());
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.encryptHeader(headerCryptor.create()).limit());
	}

	@Test
	@SuppressWarnings("deprecation")
	public void testDecryption() throws AuthenticationFailedException {
		byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfMdzvHF3f9EE0LSnRLSsu6ps3IRcJg==");
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
	public void testDecryptionWithInvalidMac1() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJa=="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidMac2() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("aAAAAAAAAAAAAAAAAAAAANyVwHiiQImjrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga26lJzstK9RUv1hj5zDC4wC9FgMfoVE1mD0HnuENuYXkJA=="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

}
