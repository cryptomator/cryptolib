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
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DecryptingReadableByteChannel;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.EncryptingWritableByteChannel;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
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
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import javax.crypto.Cipher;
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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.cryptomator.cryptolib.v2.Constants.GCM_NONCE_SIZE;
import static org.cryptomator.cryptolib.v2.Constants.GCM_TAG_SIZE;

public class FileContentCryptorImplTest {

	// AES-GCM implementation requires non-repeating nonces, still we need deterministic nonces for testing
	private static final SecureRandom CSPRNG = Mockito.spy(SecureRandomMock.cycle((byte) 0xF0, (byte) 0x0F));

	private FileHeaderImpl header;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@BeforeEach
	public void setup() {
		PerpetualMasterkey masterkey = new PerpetualMasterkey(new byte[64]);
		header = new FileHeaderImpl(new byte[FileHeaderImpl.NONCE_LEN], new FileHeaderImpl.Payload(-1, new byte[FileHeaderImpl.Payload.CONTENT_KEY_LEN]));
		headerCryptor = new FileHeaderCryptorImpl(masterkey, CSPRNG);
		fileContentCryptor = new FileContentCryptorImpl(CSPRNG);
		cryptor = Mockito.mock(Cryptor.class);
		Mockito.when(cryptor.fileContentCryptor()).thenReturn(fileContentCryptor);
		Mockito.when(cryptor.fileHeaderCryptor()).thenReturn(headerCryptor);
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws AuthenticationFailedException {
		DestroyableSecretKey fileKey = new DestroyableSecretKey(new byte[16], "AES");
		ByteBuffer ciphertext = ByteBuffer.allocate(fileContentCryptor.ciphertextChunkSize());
		ByteBuffer cleartext = ByteBuffer.allocate(fileContentCryptor.cleartextChunkSize());
		fileContentCryptor.encryptChunk(UTF_8.encode("asd"), ciphertext, 42l, new byte[12], fileKey);
		ciphertext.flip();
		fileContentCryptor.decryptChunk(ciphertext, cleartext, 42l, new byte[12], fileKey);
		cleartext.flip();
		Assertions.assertEquals(UTF_8.encode("asd"), cleartext);
	}

	@Nested
	public class Encryption {

		@BeforeEach
		public void resetGcmNonce() {
			// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
			GcmTestHelper.reset((mode, key, params) -> {
				try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
					cipher.get();
				}
			});
		}

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
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x33);
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			// echo -n "hello world" | openssl enc -aes-256-gcm -K 0 -iv 333333333333333333333333 -a
			byte[] expected = BaseEncoding.base64().decode("MzMzMzMzMzMzMzMzbYvL7CusRmzk70Kn1QxFA5WQg/hgKeba4bln");
			Assertions.assertEquals(ByteBuffer.wrap(expected), ciphertext);
		}

		@Test
		@DisplayName("encrypt chunk with offset ByteBuffer")
		public void testChunkEncryptionWithByteBufferView() {
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x33);
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
			ByteBuffer cleartext = US_ASCII.encode("12345hello world12345");
			cleartext.position(5).limit(16);
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, header);
			byte[] expected = BaseEncoding.base64().decode("MzMzMzMzMzMzMzMzbYvL7CusRmzk70Kn1QxFA5WQg/hgKeba4bln");
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
			Mockito.doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x55);
				return null;
			}).doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x77);
				return null;
			}).doAnswer(invocation -> {
				byte[] nonce = invocation.getArgument(0);
				Arrays.fill(nonce, (byte) 0x55);
				return null;
			}).when(CSPRNG).nextBytes(Mockito.any());
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
		@ValueSource(ints = {0, Constants.GCM_NONCE_SIZE + Constants.GCM_TAG_SIZE - 1, Constants.CHUNK_SIZE + 1})
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
		@DisplayName("decrypt chunk with offset ByteBuffer")
		public void testChunkDecryptionWithByteBufferView() throws AuthenticationFailedException {
			byte[] actualCiphertext = BaseEncoding.base64().decode("VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv");
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

		@DisplayName("decrypt unauthentic chunk")
		@ParameterizedTest(name = "unauthentic {1}")
		@CsvSource(value = {
				"vVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv, NONCE",
				"VVVVVVVVVVVVVVVVNHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHv, CONTENT",
				"VVVVVVVVVVVVVVVVnHVdh+EbedvPeiCwCdaTYpzn1CXQjhSh7PHV, TAG",
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
				"VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5vVVVVVVVvVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=, NONCE",
				"VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVvVVVVVVVsxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coV0=, CONTENT",
				"VVVVVVVVVVVVVVVVC+/OFHHE8UvKYTOPlrMO5rCRLAI7/zk8Hjoisja03+yi9ugeeMz1evZhxDExrawl93vf9DKQPx5VVVVVVVVVVVVVVVVSxe6Nf7RO8orsVTzHAmXlNSy1oJpDrg9coVx=, TAG",
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
