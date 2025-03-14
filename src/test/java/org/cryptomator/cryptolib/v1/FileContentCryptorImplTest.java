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
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.*;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.security.SecureRandom;
import java.util.Arrays;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

public class FileContentCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	private FileHeaderImpl header;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@BeforeEach
	public void setup() {
		PerpetualMasterkey masterkey = new PerpetualMasterkey(new byte[64]);
		header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], new FileHeaderImpl.Payload(-1, new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]));
		headerCryptor = new FileHeaderCryptorImpl(masterkey, RANDOM_MOCK);
		fileContentCryptor = new FileContentCryptorImpl(masterkey, RANDOM_MOCK);
		cryptor = Mockito.mock(Cryptor.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
	}

	@Test
	public void testMacIsValidAfterEncryption() {
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[16], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		fileContentCryptor.encryptChunk(UTF_8.encode("asd"), ciphertext, 42l, new byte[16], fileKey);
		ciphertext.flip();
		Assertions.assertTrue(fileContentCryptor.checkChunkMac(new byte[16], 42l, ciphertext));
		Assertions.assertFalse(fileContentCryptor.checkChunkMac(new byte[16], 43l, ciphertext));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() {
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[16], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		ByteBuffer cleartext = ByteBuffer.allocate(fileContentCryptor.cleartextChunkSize());
		fileContentCryptor.encryptChunk(UTF_8.encode("asd"), ciphertext, 42l, new byte[12], fileKey);
		ciphertext.flip();
		fileContentCryptor.decryptChunk(ciphertext, cleartext, fileKey);
		cleartext.flip();
		Assertions.assertEquals(UTF_8.encode("asd"), cleartext);
	}

	@Nested
	public class Encryption {

		@DisplayName("encrypt chunk with invalid size")
		@ParameterizedTest(name = "cleartext size: {0}")
		@ValueSource(ints = {Constants.PAYLOAD_SIZE + 1})
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
			ByteBuffer expected = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			Assertions.assertEquals(expected, ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with offset ByteBuffer")
		public void testChunkEncryptionWithByteBufferView() {
			ByteBuffer cleartext = US_ASCII.encode("12345hello world12345");
			cleartext.position(5).limit(16);
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			ByteBuffer expected = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			Assertions.assertEquals(expected, ciphertext);
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
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt chunk")
		public void testChunkDecryption() throws AuthenticationFailedException {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = US_ASCII.encode("hello world");
			Assertions.assertEquals(expected, cleartext);
		}

		@Test
		@DisplayName("decrypt chunk with offset ByteBuffer")
		public void testChunkDecryptionWithByteBufferView() throws AuthenticationFailedException {
			byte[] actualCiphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og=");
			ByteBuffer ciphertext = ByteBuffer.allocate(100);
			ciphertext.position(10);
			ciphertext.put(actualCiphertext);
			ciphertext.position(10).limit(10 + actualCiphertext.length);
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
				Assertions.assertThrows(EOFException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
			}
		}

		@DisplayName("decrypt unauthentic chunk")
		@ParameterizedTest(name = "unauthentic {1}")
		@CsvSource(value = {
				"aAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og=, NONCE",
				"AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3YTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og=, CONTENT",
				"AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG=, MAC",
		})
		public void testUnauthenticChunkDecryption(String chunkData, String ignored) {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode(chunkData));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@DisplayName("decrypt unauthentic file")
		@ParameterizedTest(name = "unauthentic {1} in first chunk")
		@CsvSource(value = {
				"AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo, NONCE",
				"AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUZWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo, CONTENT",
				"AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO, MAC",
		})
		public void testDecryptionWithUnauthenticFirstChunk(String fileData, String ignored) throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode(fileData);

			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic MAC but skipping MAC verficiation")
		public void testChunkDecryptionWithUnauthenticMacSkipAuth() throws AuthenticationFailedException {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, false);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assertions.assertEquals(expected, cleartext);
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
