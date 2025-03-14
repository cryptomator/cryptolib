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
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.cryptomator.siv.UnauthenticCiphertextException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.UUID;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;

public class FileNameCryptorImplTest {

	private static final BaseEncoding BASE32 = BaseEncoding.base32();

	private final PerpetualMasterkey masterkey = new PerpetualMasterkey(new byte[64]);
	private final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(masterkey);

	private static Stream<String> filenameGenerator() {
		return Stream.generate(UUID::randomUUID).map(UUID::toString).limit(100);
	}

	@DisplayName("encrypt and decrypt file names")
	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	public void testDeterministicEncryptionOfFilenames(String origName) throws AuthenticationFailedException {
		String encrypted1 = filenameCryptor.encryptFilename(BASE32, origName);
		String encrypted2 = filenameCryptor.encryptFilename(BASE32, origName);
		String decrypted = filenameCryptor.decryptFilename(BASE32, encrypted1);

		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertEquals(origName, decrypted);
	}

	@DisplayName("encrypt and decrypt file names with AD and custom encoding")
	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	public void testDeterministicEncryptionOfFilenamesWithCustomEncodingAndAssociatedData(String origName) throws AuthenticationFailedException {
		byte[] associdatedData = new byte[10];
		String encrypted1 = filenameCryptor.encryptFilename(BaseEncoding.base64Url(), origName, associdatedData);
		String encrypted2 = filenameCryptor.encryptFilename(BaseEncoding.base64Url(), origName, associdatedData);
		String decrypted = filenameCryptor.decryptFilename(BaseEncoding.base64Url(), encrypted1, associdatedData);

		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertEquals(origName, decrypted);
	}

	@Test
	@DisplayName("encrypt and decrypt 128 bit filename")
	public void testDeterministicEncryptionOf128bitFilename() throws AuthenticationFailedException {
		// block size length file names
		String originalPath3 = "aaaabbbbccccdddd"; // 128 bit ascii
		String encryptedPath3a = filenameCryptor.encryptFilename(BASE32, originalPath3);
		String encryptedPath3b = filenameCryptor.encryptFilename(BASE32, originalPath3);
		String decryptedPath3 = filenameCryptor.decryptFilename(BASE32, encryptedPath3a);

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
			filenameCryptor.decryptFilename(BASE32, "lol");
		});
		MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(IllegalArgumentException.class));
	}

	@Test
	@DisplayName("decrypt tampered ciphertext")
	public void testDecryptionOfManipulatedFilename() {
		final byte[] encrypted = filenameCryptor.encryptFilename(BASE32, "test").getBytes(UTF_8);
		encrypted[0] ^= (byte) 0x01; // change 1 bit in first byte
		String ciphertextName = new String(encrypted, UTF_8);

		AuthenticationFailedException e = Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(BASE32, ciphertextName);
		});
		MatcherAssert.assertThat(e.getCause(), CoreMatchers.instanceOf(UnauthenticCiphertextException.class));
	}

	@Test
	@DisplayName("encrypt with different AD")
	public void testEncryptionOfSameFilenamesWithDifferentAssociatedData() {
		final String encrypted1 = filenameCryptor.encryptFilename(BASE32, "test", "ad1".getBytes(UTF_8));
		final String encrypted2 = filenameCryptor.encryptFilename(BASE32, "test", "ad2".getBytes(UTF_8));
		Assertions.assertNotEquals(encrypted1, encrypted2);
	}

	@Test
	@DisplayName("decrypt ciphertext with correct AD")
	public void testDeterministicEncryptionOfFilenamesWithAssociatedData() throws AuthenticationFailedException {
		final String encrypted = filenameCryptor.encryptFilename(BASE32, "test", "ad".getBytes(UTF_8));
		final String decrypted = filenameCryptor.decryptFilename(BASE32, encrypted, "ad".getBytes(UTF_8));
		Assertions.assertEquals("test", decrypted);
	}

	@Test
	@DisplayName("decrypt ciphertext with incorrect AD")
	public void testDeterministicEncryptionOfFilenamesWithWrongAssociatedData() {
		final String encrypted = filenameCryptor.encryptFilename(BASE32, "test", "right".getBytes(UTF_8));
		final byte[] ad = "wrong".getBytes(UTF_8);

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(BASE32, encrypted, ad);
		});
	}

}
