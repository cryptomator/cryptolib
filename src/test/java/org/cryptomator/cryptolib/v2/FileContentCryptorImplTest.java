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
import org.cryptomator.cryptolib.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.cryptomator.cryptolib.common.SeekableByteChannelMock;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
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
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

public class FileContentCryptorImplTest {

	private SecureRandom csprng;
	private FileHeaderImpl header;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@BeforeEach
	public void setup() {
		csprng = SecureRandomMock.cycle((byte) 0x55, (byte) 0x77); // AES-GCM implementation requires non-repeating nonces, still we need deterministic nonces for testing
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		header = new FileHeaderImpl(new byte[12], new byte[32]);
		headerCryptor = new FileHeaderCryptorImpl(encKey, csprng);
		fileContentCryptor = new FileContentCryptorImpl(csprng);
		cryptor = Mockito.mock(Cryptor.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws AuthenticationFailedException {
		SecretKey fileKey = new SecretKeySpec(new byte[16], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		ByteBuffer cleartext = ByteBuffer.allocate(fileContentCryptor.cleartextChunkSize());
		fileContentCryptor.encryptChunk(StandardCharsets.UTF_8.encode("asd"), ciphertext, 42l, new byte[12], fileKey);
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
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			// echo -n "hello world" | openssl enc -aes-256-gcm -K 0 -iv 555555555555555555555555 -a
			byte[] expected = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv");
			Assertions.assertEquals(ByteBuffer.wrap(expected), ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with too small ciphertext buffer")
		public void testChunkEncryptionWithBufferUnderflow() {
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
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
				ch.write(StandardCharsets.US_ASCII.encode("hello world"));
			}
			dst.flip();
			byte[] ciphertext = new byte[dst.remaining()];
			dst.get(ciphertext);
			byte[] expected = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			Assertions.assertArrayEquals(expected, ciphertext);
		}

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
		public void testChunkDecryption() throws AuthenticationFailedException {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv"));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			ByteBuffer expected = StandardCharsets.US_ASCII.encode("hello world");
			Assertions.assertEquals(expected, cleartext);
		}

		@Test
		@DisplayName("decrypt chunk with too small cleartext buffer")
		public void testChunkDecryptionWithBufferUnderflow() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv"));
			ByteBuffer cleartext = ByteBuffer.allocate(Constants.PAYLOAD_SIZE - 1);
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, cleartext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt file")
		public void testFileDecryption() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				int read = cleartextCh.read(result);
				Assertions.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(StandardCharsets.US_ASCII);
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

		@Test
		@DisplayName("decrypt chunk with unauthentic NONCE")
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("vVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic NONCE in first chunk")
		public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5vVVVVVVVvVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic CONTENT")
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVNHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic CONTENT in first chunk")
		public void testDecryptionWithUnauthenticContent() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVvVVVVVVVsxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

		@Test
		@DisplayName("decrypt chunk with unauthentic tag")
		public void testChunkDecryptionWithUnauthenticTag() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHV"));

			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				fileContentCryptor.decryptChunk(ciphertext, 0, header, true);
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic tag in first chunk")
		public void testDecryptionWithUnauthenticTag() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coVx=");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				IOException thrown = Assertions.assertThrows(IOException.class, () -> {
					cleartextCh.read(ByteBuffer.allocate(3));
				});
				MatcherAssert.assertThat(thrown.getCause(), CoreMatchers.instanceOf(AuthenticationFailedException.class));
			}
		}

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
