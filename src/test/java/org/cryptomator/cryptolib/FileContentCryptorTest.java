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
import org.spongycastle.util.encoders.Base64;

public class FileContentCryptorTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private SecretKey encKey;
	private SecretKey macKey;
	private FileContentCryptor fileContentCryptor;

	@Before
	public void setup() {
		encKey = new SecretKeySpec(new byte[32], "AES");
		macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
		fileContentCryptor = new FileContentCryptor(encKey, macKey, RANDOM_MOCK);
	}

	@Test
	public void testEncryption() throws IOException {
		byte[] cleartext = "hello world".getBytes(StandardCharsets.UTF_8);
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

	@Test
	public void testDecryption() throws IOException {
		byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
				+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
		ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		WritableByteChannel out = Channels.newChannel(result);
		fileContentCryptor.decryptFile(in, out, true);
		byte[] cleartext = result.toByteArray();
		byte[] expected = "hello world".getBytes(StandardCharsets.UTF_8);
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
		byte[] expected = "hello world".getBytes(StandardCharsets.UTF_8);
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
	public void testDecryptionWithUnauthenticNonce() throws InterruptedException, IOException {
		byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
				+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAABAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzo");
		ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		WritableByteChannel out = Channels.newChannel(result);
		fileContentCryptor.decryptFile(in, out, true);
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
	public void testDecryptionWithUnauthenticMac() throws InterruptedException, IOException {
		byte[] ciphertext = Base64.decode("AAAAAAAAAAAAAAAAAAAAANyVwHiiQImCrUiiFJKEIIdTD4r7x0U2ualjtPHEy3OLzqdAPU1ga27XjlTjFxC1VCqZa+" //
				+ "L2eH+xWVgrSLX+JkG35ZJxk5xXswAAAAAAAAAAAAAAAAAAAAC08KwUzWD+5t8kxipYZGvVj719S6Z+RGH1cZcl9SEoEV7XUZ4rzO6+hdzO");
		ReadableByteChannel in = Channels.newChannel(new ByteArrayInputStream(ciphertext));
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		WritableByteChannel out = Channels.newChannel(result);
		fileContentCryptor.decryptFile(in, out, true);
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
		byte[] expected = "hello world".getBytes(StandardCharsets.UTF_8);
		Assert.assertArrayEquals(expected, cleartext);
	}

}
