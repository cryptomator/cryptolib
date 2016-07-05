/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.spongycastle.util.encoders.Base64;

import de.bechte.junit.runners.context.HierarchicalContextRunner;

@RunWith(HierarchicalContextRunner.class)
public class FileContentCryptorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private FileHeaderCryptor headerCryptor;
	private FileContentCryptor fileContentCryptor;

	@Before
	public void setup() {
		SecretKey encKey = new SecretKeySpec(new byte[32], "AES");
		SecretKey macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
		headerCryptor = new FileHeaderCryptor(encKey, macKey, RANDOM_MOCK);
		fileContentCryptor = new FileContentCryptor(macKey, RANDOM_MOCK, headerCryptor);
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
			ByteBuffer cleartext = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			ByteBuffer ciphertext = fileContentCryptor.encryptChunk(cleartext, 0, headerCryptor.create());
			ByteBuffer expected = ByteBuffer.wrap(Base64.decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			Assert.assertArrayEquals(expected.array(), ciphertext.array());
		}

		@Test
		public void testEncryption() throws IOException {
			byte[] cleartext = "hello world".getBytes(StandardCharsets.US_ASCII);
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(cleartext));
			Path tmpPath = Files.createTempFile("unit-test", null);
			SeekableByteChannel out = Files.newByteChannel(tmpPath, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
			fileContentCryptor.encryptFile(in, out);
			byte[] ciphertext = Files.readAllBytes(tmpPath);
			byte[] expected = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			Files.deleteIfExists(tmpPath);
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
			ByteBuffer ciphertext = ByteBuffer.allocate(40000);
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test
		public void testChunkDecryption() {
			ByteBuffer ciphertext = ByteBuffer.wrap(Base64.decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
			ByteBuffer expected = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assert.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		public void testDecryption() throws IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
			byte[] cleartext = result.toByteArray();
			byte[] expected = "hello world".getBytes(StandardCharsets.US_ASCII);
			Assert.assertArrayEquals(expected, cleartext);
		}

		@Test
		public void testDecryptionWithRandomPadding() throws IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxlXBwKLpaM/JtOX+KdCbx53bCAFI63RFRPAhpViOkN4btnrI");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
			byte[] cleartext = result.toByteArray();
			byte[] expected = "hello world".getBytes(StandardCharsets.US_ASCII);
			Assert.assertArrayEquals(expected, cleartext);
		}

		@Test(expected = IllegalArgumentException.class)
		public void testDecryptionWithTooShortHeader() throws InterruptedException, IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAA");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticNonce() {
			ByteBuffer ciphertext = ByteBuffer.wrap(Base64.decode("aAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticContent() {
			ByteBuffer ciphertext = ByteBuffer.wrap(Base64.decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3YTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3Og="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticContent() throws InterruptedException, IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUZWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testChunkDecryptionWithUnauthenticMac() {
			ByteBuffer ciphertext = ByteBuffer.wrap(Base64.decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), true);
		}

		@Test(expected = AuthenticationFailedException.class)
		public void testDecryptionWithUnauthenticMac() throws InterruptedException, IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, true);
		}

		@Test
		public void testChunkDecryptionWithUnauthenticMacSkipAuth() {
			ByteBuffer ciphertext = ByteBuffer.wrap(Base64.decode("AAAAAAAAAAAAAAAAAAAAALTwrBTNYP7m3yTGKlhka9WPvX1Lpn5EYfVxlyX1ISgRXtdRnivM7r6F3OG="));
			ByteBuffer cleartext = fileContentCryptor.decryptChunk(ciphertext, 0, headerCryptor.create(), false);
			ByteBuffer expected = StandardCharsets.US_ASCII.encode(CharBuffer.wrap("hello world"));
			Assert.assertArrayEquals(expected.array(), cleartext.array());
		}

		@Test
		public void testDecryptionWithUnauthenticMacSkipAuth() throws InterruptedException, IOException {
			byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
					+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
			ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
			ByteArrayOutputStream result = new ByteArrayOutputStream();
			WritableByteChannel out = Channels.newChannel(result);
			fileContentCryptor.decryptFile(in, out, false);
			byte[] cleartext = result.toByteArray();
			byte[] expected = "hello world".getBytes(StandardCharsets.US_ASCII);
			Assert.assertArrayEquals(expected, cleartext);
		}

	}

}
