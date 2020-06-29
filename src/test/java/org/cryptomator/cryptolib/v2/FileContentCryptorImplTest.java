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
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

public class FileContentCryptorImplTest {

	private static final Charset US_ASCII = Charset.forName("US-ASCII");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final SecureRandom ANTI_REUSE_PRNG = SecureRandomMock.cycle((byte) 0x13, (byte) 0x37);

	private FileHeaderImpl header;
	private FileContentCryptorImpl fileContentCryptor;

	@BeforeEach
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
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		ByteBuffer cleartext = ByteBuffer.allocate(fileContentCryptor.cleartextChunkSize());
		fileContentCryptor.encryptChunk(StandardCharsets.UTF_8.encode("asd"), ciphertext,42l, new byte[12], fileKey);
		ciphertext.flip();
		fileContentCryptor.decryptChunk(ciphertext, cleartext, 42l, new byte[12], fileKey);
		cleartext.flip();
		Assertions.assertEquals(StandardCharsets.UTF_8.encode("asd"), cleartext);
	}

	@Nested
	public class Encryption {

		@DisplayName("encrypt chunk with invalid size")
		@ParameterizedTest(name = "cleartext size: {0}")
		@ValueSource(ints = {0, org.cryptomator.cryptolib.v2.Constants.PAYLOAD_SIZE + 1})
		public void testEncryptChunkOfInvalidSize(int size) {
			ByteBuffer cleartext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, 0, header);
			});
		}

		@Test
		@DisplayName("encrypt chunk")
		public void testChunkEncryption() {
			ByteBuffer cleartext = US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			// echo -n "hello world" | openssl enc -aes-256-gcm -K 0 -iv 0 -a
			byte[] expected = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq");
			Assertions.assertEquals(ByteBuffer.wrap(expected), ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with too small ciphertext buffer")
		public void testChunkEncryptionWithBufferUnderflow() {
			ByteBuffer cleartext = US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.CHUNK_SIZE - 1);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, ciphertext, 0, header);
			});
		}

//		@Test
//		@DisplayName("encrypt file")
//		public void testFileEncryption() throws IOException {
//			ByteBuffer dst = ByteBuffer.allocate(200);
//			SeekableByteChannel dstCh = new SeekableByteChannelMock(dst);
//			try (WritableByteChannel ch = new EncryptingWritableByteChannel(dstCh, cryptor)) {
//				ch.write(US_ASCII.encode("hello world"));
//			}
//			byte[] ciphertext = new byte[147];
//			dst.position(0);
//			dst.get(ciphertext);
//			byte[] expected = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfM" //
//					+ "dzvHF3f9EE0LSnRLSsu6ps3IRcJgAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
//			Assertions.assertArrayEquals(expected, ciphertext);
//		}

	}

	@Nested
	public class Decryption {

		@DisplayName("decrypt chunk with invalid size")
		@ParameterizedTest(name = "ciphertext size: {0}")
		@ValueSource(ints = {0, Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE - 1, org.cryptomator.cryptolib.v2.Constants.CHUNK_SIZE + 1})
		public void testDecryptChunkOfInvalidSize(int size) {
			ByteBuffer ciphertext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt chunk")
		public void testChunkDecryption() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = US_ASCII.encode("hello world");
			Assertions.assertEquals(expected, cleartext);
		}

		@Test
		@DisplayName("decrypt chunk with too small cleartext buffer")
		public void testChunkDecryptionWithBufferUnderflow() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));
			ByteBuffer cleartext = ByteBuffer.allocate(Constants.PAYLOAD_SIZE - 1);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, cleartext, 0, header, true);
			});
		}

//		@Test
//		@DisplayName("decrypt file")
//		public void testFileDecryption() throws IOException {
//			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
//					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
//			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));
//
//			ByteBuffer result = ByteBuffer.allocate(20);
//			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
//				int read = cleartextCh.read(result);
//				Assertions.assertEquals(11, read);
//				byte[] expected = "hello world".getBytes(US_ASCII);
//				Assertions.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
//			}
//		}

//		@Test
//		@DisplayName("decrypt file with unauthentic file header")
//		public void testDecryptionWithTooShortHeader() throws InterruptedException, IOException {
//			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAA");
//			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));
//
//			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
//				Assertions.assertThrows(IllegalArgumentException.class, () -> {
//					cleartextCh.read(ByteBuffer.allocate(3));
//				});
//			}
//		}

		@Test
		@DisplayName("decrypt chunk with unauthentic NONCE")
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("aAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736Xq"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

//		@Test
//		@DisplayName("decrypt file with unauthentic NONCE in first chunk")
//		public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
//			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
//					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
//			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));
//
//			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
//				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
//					cleartextCh.read(ByteBuffer.allocate(3));
//				});
//			}
//		}

		@Test
		@DisplayName("decrypt chunk with unauthentic CONTENT")
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqqqqqqqEvceoFIiAj5736Xq"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

//		@Test
//		@DisplayName("decrypt file with unauthentic CONTENT in first chunk")
//		public void testDecryptionWithUnauthenticContent() throws InterruptedException, IOException {
//			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
//					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUZWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
//			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));
//
//			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
//				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
//					cleartextCh.read(ByteBuffer.allocate(3));
//				});
//			}
//		}

		@Test
		@DisplayName("decrypt chunk with unauthentic tag")
		public void testChunkDecryptionWithUnauthenticTag() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAApsIsUSJAHAF1IqG66PAqEvceoFIiAj5736XQ"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

//		@Test
//		@DisplayName("decrypt file with unauthentic MAC in first chunk")
//		public void testDecryptionWithUnauthenticMac() throws InterruptedException, IOException {
//			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
//					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
//			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));
//
//			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
//				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
//					cleartextCh.read(ByteBuffer.allocate(3));
//				});
//			}
//		}

		@Test
		@DisplayName("decrypt chunk with unauthentic tag but skipping authentication")
		public void testChunkDecryptionWithUnauthenticTagSkipAuth() {
			ByteBuffer dummyCiphertext = ByteBuffer.allocate(GCM_NONCE_SIZE + GCM_TAG_SIZE);
			FileHeader header = Mockito.mock(FileHeader.class);
			Assertions.assertThrows(UnsupportedOperationException.class, () -> {
				fileContentCryptor.decryptChunk(dummyCiphertext, 0, header, false);
			});
		}

	}

}
