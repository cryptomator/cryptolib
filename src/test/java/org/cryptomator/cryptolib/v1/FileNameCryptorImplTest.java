/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.siv.UnauthenticCiphertextException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class FileNameCryptorImplTest {

	private static final Charset UTF_8 = Charset.forName("UTF-8");

	final byte[] keyBytes = new byte[32];
	final SecretKey encryptionKey = new SecretKeySpec(keyBytes, "AES");
	final SecretKey macKey = new SecretKeySpec(keyBytes, "AES");
	final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

	static Stream<String> filenameGenerator() {
		return Stream.generate(UUID::randomUUID).map(UUID::toString).limit(100);
	}

	@DisplayName("encrypt and decrypt file names")
	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	public void testDeterministicEncryptionOfFilenames(String origName) {
		String encrypted1 = filenameCryptor.encryptFilename(origName);
		String encrypted2 = filenameCryptor.encryptFilename(origName);
		String decrypted = filenameCryptor.decryptFilename(encrypted1);

		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertEquals(origName, decrypted);
	}

	@DisplayName("encrypt and decrypt file names with AD and custom encoding")
	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	public void testDeterministicEncryptionOfFilenamesWithCustomEncodingAndAssociatedData(String origName) {
		byte[] associdatedData = new byte[10];
		String encrypted1 = filenameCryptor.encryptFilename(BaseEncoding.base64Url(), origName, associdatedData);
		String encrypted2 = filenameCryptor.encryptFilename(BaseEncoding.base64Url(), origName, associdatedData);
		String decrypted = filenameCryptor.decryptFilename(BaseEncoding.base64Url(), encrypted1, associdatedData);

		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertEquals(origName, decrypted);
	}

	@Test
	@DisplayName("encrypt and decrypt 128 bit filename")
	public void testDeterministicEncryptionOf128bitFilename() {
		// block size length file names
		String originalPath3 = "aaaabbbbccccdddd"; // 128 bit ascii
		String encryptedPath3a = filenameCryptor.encryptFilename(originalPath3);
		String encryptedPath3b = filenameCryptor.encryptFilename(originalPath3);
		String decryptedPath3 = filenameCryptor.decryptFilename(encryptedPath3a);

		Assertions.assertEquals(encryptedPath3a, encryptedPath3b);
		Assertions.assertEquals(originalPath3, decryptedPath3);
	}

	@DisplayName("hash directory id for random directory ids")
	@ParameterizedTest(name = "hashDirectoryId({0})")
	@MethodSource("filenameGenerator")
	public void testDeterministicHashingOfDirectoryIds(String originalDirectoryId) {
		final String hashedDirectory1 = filenameCryptor.hashDirectoryId(originalDirectoryId);
		final String hashedDirectory2 = filenameCryptor.hashDirectoryId(originalDirectoryId);
		Assertions.assertEquals(hashedDirectory1, hashedDirectory2);
	}

	@Test
	@DisplayName("decrypt non-ciphertext")
	public void testDecryptionOfMalformedFilename() {
		AuthenticationFailedException e = Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename("lol");
		});
		MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(IllegalArgumentException.class));
	}

	@Test
	@DisplayName("decrypt tampered ciphertext")
	public void testDecryptionOfManipulatedFilename() {
		final byte[] encrypted = filenameCryptor.encryptFilename("test").getBytes(UTF_8);
		encrypted[0] ^= (byte) 0x01; // change 1 bit in first byte

		AuthenticationFailedException e = Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(new String(encrypted, UTF_8));
		});
		MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(UnauthenticCiphertextException.class));
	}

	@Test
	@DisplayName("encrypt with different AD")
	public void testEncryptionOfSameFilenamesWithDifferentAssociatedData() {
		final String encrypted1 = filenameCryptor.encryptFilename("test", "ad1".getBytes(UTF_8));
		final String encrypted2 = filenameCryptor.encryptFilename("test", "ad2".getBytes(UTF_8));
		Assertions.assertNotEquals(encrypted1, encrypted2);
	}

	@Test
	@DisplayName("decrypt ciphertext with correct AD")
	public void testDeterministicEncryptionOfFilenamesWithAssociatedData() {
		final String encrypted = filenameCryptor.encryptFilename("test", "ad".getBytes(UTF_8));
		final String decrypted = filenameCryptor.decryptFilename(encrypted, "ad".getBytes(UTF_8));
		Assertions.assertEquals("test", decrypted);
	}

	@Test
	@DisplayName("decrypt ciphertext with incorrect AD")
	public void testDeterministicEncryptionOfFilenamesWithWrongAssociatedData() {
		final String encrypted = filenameCryptor.encryptFilename("test", "right".getBytes(UTF_8));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(encrypted, "wrong".getBytes(UTF_8));
		});
	}

}
