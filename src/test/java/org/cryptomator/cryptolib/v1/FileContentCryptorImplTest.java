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
import org.cryptomator.cryptolib.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.common.SeekableByteChannelMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class FileContentCryptorImplTest {

	private static final Charset US_ASCII = Charset.forName("US-ASCII");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@BeforeEach
	public void setup() {
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		SecretKey macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
		headerCryptor = new FileHeaderCryptorImpl(encKey, macKey, RANDOM_MOCK);
		fileContentCryptor = new FileContentCryptorImpl(macKey, RANDOM_MOCK);
		cryptor = Mockito.mock(Cryptor.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
	}

	@Test
	public void testMacIsValidAfterEncryption() throws NoSuchAlgorithmException {
		SecretKey fileKey = new SecretKeySpec(new byte[16], "AES");
		ByteBuffer result = fileContentCryptor.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[16], fileKey);
		Assertions.assertTrue(fileContentCryptor.checkChunkMac(new byte[16], 42l, result));
		Assertions.assertFalse(fileContentCryptor.checkChunkMac(new byte[16], 43l, result));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws NoSuchAlgorithmException {
		SecretKey fileKey = new SecretKeySpec(new byte[16], "AES");
		ByteBuffer ciphertext = fileContentCryptor.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[16], fileKey);
		ByteBuffer result = fileContentCryptor.decryptChunk(ciphertext, fileKey);
		Assertions.assertArrayEquals("asd".getBytes(), result.array());
	}

	@Nested
	public class Encryption {

		@DisplayName("encrypt chunk with invalid size")
		@ParameterizedTest(name = "cleartext size: {0}")
		@ValueSource(ints = {0, Constants.PAYLOAD_SIZE + 1})
		public void testEncryptChunkOfInvalidSize(int size) {
			ByteBuffer cleartext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
			});
		}

		@Test
		@DisplayName("encrypt chunk")
		public void testChunkEncryption() {
			ByteBuffer cleartext = US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
			ByteBuffer expected = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			Assertions.assertArrayEquals(expected.array(), ciphertext.array());
		}

		@Test
		@DisplayName("encrypt file")
		public void testFileEncryption() throws IOException {
			ByteBuffer dst = ByteBuffer.allocate(200);
			SeekableByteChannel dstCh = new SeekableByteChannelMock(dst);
			try (WritableByteChannel ch = new EncryptingWritableByteChannel(dstCh, cryptor)) {
				ch.write(US_ASCII.encode("hello world"));
			}
			byte[] ciphertext = new byte[147];
			dst.position(0);
			dst.get(ciphertext);
			byte[] expected = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAACNqP4ddv3Z2rUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga24VjC86+zlHN49BfM" //
					+ "dzvHF3f9EE0LSnRLSsu6ps3IRcJgAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			Assertions.assertArrayEquals(expected, ciphertext);
		}

	}

	@Nested
	public class Decryption {

		@DisplayName("decrypt chunk with invalid size")
		@ParameterizedTest(name = "ciphertext size: {0}")
		@ValueSource(ints = {0, Constants.NONCE_SIZE + Constants.MAC_SIZE - 1, Constants.CHUNK_SIZE + 1})
		public void testDecryptChunkOfInvalidSize(int size) {
			ByteBuffer ciphertext = ByteBuffer.allocate(size);

			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			});
		}

		@Test
		@DisplayName("decrypt chunk")
		public void testChunkDecryption() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assertions.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		@DisplayName("decrypt file")
		public void testFileDecryption() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				int read = cleartextCh.read(result);
				Assertions.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(US_ASCII);
				Assertions.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
			}
		}

		@Test
		@DisplayName("decrypt file with unauthentic file header")
		public void testDecryptionWithTooShortHeader() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAA");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				Assertions.assertThrows(IllegalArgumentException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic NONCE")
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("aAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic NONCE in first chunk")
		public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic CONTENT")
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3YTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic CONTENT in first chunk")
		public void testDecryptionWithUnauthenticContent() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUZWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic MAC")
		public void testChunkDecryptionWithUnauthenticMac() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic MAC in first chunk")
		public void testDecryptionWithUnauthenticMac() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				Assertions.assertThrows(AuthenticationFailedException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic MAC but skipping MAC verficiation")
		public void testChunkDecryptionWithUnauthenticMacSkipAuth() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), false);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assertions.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		@DisplayName("decrypt file with unauthentic MAC in first chunk but skipping MAC verficiation")
		public void testDecryptionWithUnauthenticMacSkipAuth() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, false)) {
				int read = cleartextCh.read(result);
				Assertions.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(US_ASCII);
				Assertions.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
			}
		}

	}

}
