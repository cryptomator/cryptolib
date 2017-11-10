/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;

import com.google.common.io.BaseEncoding;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class FileContentCryptorImplTest {

	private static final Charset US_ASCII = Charset.forName("US-ASCII");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private FileHeaderCryptorImpl headerCryptor;
	private FileContentCryptorImpl fileContentCryptor;
	private Cryptor cryptor;

	@Before
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
		Assert.assertTrue(fileContentCryptor.checkChunkMac(new byte[16], 42l, result));
		Assert.assertFalse(fileContentCryptor.checkChunkMac(new byte[16], 43l, result));
	}

	@Test
	public void testDecryptedEncryptedEqualsPlaintext() throws NoSuchAlgorithmException {
		SecretKey fileKey = new SecretKeySpec(new byte[16], "AES");
		ByteBuffer ciphertext = fileContentCryptor.encryptChunk(ByteBuffer.wrap("asd".getBytes()), 42l, new byte[16], fileKey);
		ByteBuffer result = fileContentCryptor.decryptChunk(ciphertext, fileKey);
		Assert.assertArrayEquals("asd".getBytes(), result.array());
	}

	public class Encryption {

		@Test(expected = IllegalArgumentException.class)
		public void testChunkEncryptionWithInvalidChunk1() {
			ByteBuffer cleartext = ByteBuffer.allocate(0);
			fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkEncryptionWithInvalidChunk2() {
			ByteBuffer cleartext = ByteBuffer.allocate(40000);
			fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
		}

		@Test
		public void testChunkEncryption() {
			ByteBuffer cleartext = US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
			ByteBuffer expected = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			Assert.assertArrayEquals(expected.array(), ciphertext.array());
		}

		@Test
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
			Assert.assertArrayEquals(expected, ciphertext);
		}

	}

	public class Decryption {

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunk1() {
			ByteBuffer ciphertext = ByteBuffer.allocate(0);
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunk2() {
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.NONCE_SIZE + Constants.MAC_SIZE - 1);
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testChunkDecryptionWithInvalidChunk3() {
			ByteBuffer ciphertext = ByteBuffer.allocate(Constants.CHUNK_SIZE + 1);
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test
		public void testChunkDecryption() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assert.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		public void testDecryption() throws IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				int read = cleartextCh.read(result);
				Assert.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(US_ASCII);
				Assert.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
			}
		}

		@Test(expected = IllegalArgumentException.class)
		public void testDecryptionWithTooShortHeader() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAA");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				cleartextCh.read(ByteBuffer.allocate(3));
			}
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("aAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				cleartextCh.read(ByteBuffer.allocate(3));
			}
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3YTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticContent() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUZWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				cleartextCh.read(ByteBuffer.allocate(3));
			}
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticMac() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticMac() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, true)) {
				cleartextCh.read(ByteBuffer.allocate(3));
			}
		}

		@Test
		public void testChunkDecryptionWithUnauthenticMacSkipAuth() {
			ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), false);
			ByteBuffer expected = US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assert.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		public void testDecryptionWithUnauthenticMacSkipAuth() throws InterruptedException, IOException {
			byte[] ciphertext = BaseEncoding.base64().decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel ciphertextCh = Channels.newChannel(new ByteArrayInputStream(ciphertext));

			ByteBuffer result = ByteBuffer.allocate(20);
			try (ReadableByteChannel cleartextCh = new DecryptingReadableByteChannel(ciphertextCh, cryptor, false)) {
				int read = cleartextCh.read(result);
				Assert.assertEquals(11, read);
				byte[] expected = "hello world".getBytes(US_ASCII);
				Assert.assertArrayEquals(expected, Arrays.copyOfRange(result.array(), 0, read));
			}
		}

	}

}
