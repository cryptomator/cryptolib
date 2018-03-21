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
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.io.BaseEncoding;
import de.bechte.junit.runners.context.HierarchicalContextRunner;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

@RunWith(HierarchicalContextRunner.class)
public class FileContentCryptorImplTest {

	private static final Charset US_ASCII = Charset.forName("US-ASCII");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final SecureRandom ANTI_REUSE_PRNG = SecureRandomMock.cycle((byte) 0x13, (byte) 0x37);

	private FileHeaderImpl header;
	private FileContentCryptorImpl fileContentCryptor;

	@Before
	public void setup() {
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		header = new FileHeaderImpl(new byte[12], new byte[32]);
		fileContentCryptor = new FileContentCryptorImpl(RANDOM_MOCK);

		// init cipher with distinct IV to avoid cipher-internal anti-reuse checking
		byte[] nonce = new byte[GCM_NONCE_SIZE];
		ANTI_REUSE_PRNG.nextBytes(nonce);
		CipherSupplier.AES_GCM.forEncryption(encKey, new GCMParameterSpec(GCM_TAG_SIZE * Byte.SIZE, nonce));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws NoSuchAlgorithmException {
		SecretKey fileKey = new SecretKeySpec(new byte[16], "AES");
		ByteBuffer ciphertext = fileContentCryptor.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[12], fileKey);
		ByteBuffer result = fileContentCryptor.decryptChunk(ciphertext, 42l, new byte[12], fileKey);
		Assert.assertArrayEquals("asd".getBytes(), result.array());
	}

	public class Encryption {

		@Test(expected = IllegalArgumentException.class)
		public void testChunkEncryptionWithInvalidChunk1() {
			ByteBuffer cleartext = ByteBuffer.allocate(0);
			fileContentCryptor.encryptChunk(cleartext, 0, header);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkEncryptionWithInvalidChunk2() {
			ByteBuffer cleartext = ByteBuffer.allocate(40000);
			fileContentCryptor.encryptChunk(cleartext, 0, header);
		}

		@Test
		public void testChunkEncryption() {
			FileHeader header = new FileHeaderImpl(new byte[12], new byte[32]);
			ByteBuffer cleartext = US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			// echo -n "hello world" | openssl enc -aes-256-gcm -K 0 -iv 0 -a
			ByteBuffer expected = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			Assert.assertArrayEquals(expected.array(), ciphertext.array());
		}

	}

	public class Decryption {

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunkLength1() {
			ByteBuffer ciphertext = ByteBuffer.allocate(0);
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunkLength2() {
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE - 1);
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunkLength3() {
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.CHUNK_SIZE + 1);
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test
		public void testChunkDecryption() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assert.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("aAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAPsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticTag() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736XQ"));
			fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
		}

		@Test(expected = UnsupportedOperationException.class)
		public void testChunkDecryptionWithUnauthenticTagSkipAuth() {
			ByteBuffer dummyCiphertext = ByteBuffer.allocate(GCM_NONCE_SIZE + GCM_TAG_SIZE);
			FileHeader header = Mockito.mock(FileHeader.class);
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(dummyCiphertext, 0, header, false);
		}

	}

}
