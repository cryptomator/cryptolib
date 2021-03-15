/*******************************************************************************
 * Copyright (c) 2015, 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v2;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.UUID;


public class FileNameCryptorImplTest {

	private static final Charset UTF_8 = StandardCharsets.UTF_8;

	@Test
	public void testDeterministicEncryptionOfFilenames() throws AuthenticationFailedException {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		// some random
		for (int i = 0; i < 2000; i++) {
			final String origName = UUID.randomUUID().toString();
			final String encrypted1 = filenameCryptor.encryptFilename(origName);
			final String encrypted2 = filenameCryptor.encryptFilename(origName);
			Assertions.assertEquals(encrypted1, encrypted2);
			final String decrypted = filenameCryptor.decryptFilename(encrypted1);
			Assertions.assertEquals(origName, decrypted);
		}

		// block size length file names
		final String originalPath3 = "aaaabbbbccccdddd"; // 128 bit ascii
		final String encryptedPath3a = filenameCryptor.encryptFilename(originalPath3);
		final String encryptedPath3b = filenameCryptor.encryptFilename(originalPath3);
		Assertions.assertEquals(encryptedPath3a, encryptedPath3b);
		final String decryptedPath3 = filenameCryptor.decryptFilename(encryptedPath3a);
		Assertions.assertEquals(originalPath3, decryptedPath3);
	}

	@Test
	public void testDeterministicHashingOfDirectoryIds() throws IOException {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		// some random
		for (int i = 0; i < 2000; i++) {
			final String originalDirectoryId = UUID.randomUUID().toString();
			final String hashedDirectory1 = filenameCryptor.hashDirectoryId(originalDirectoryId);
			final String hashedDirectory2 = filenameCryptor.hashDirectoryId(originalDirectoryId);
			Assertions.assertEquals(hashedDirectory1, hashedDirectory2);
		}
	}

	@Test
	public void testDecryptionOfManipulatedFilename() {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		final byte[] encrypted = filenameCryptor.encryptFilename("test").getBytes(UTF_8);
		encrypted[0] ^= (byte) 0x01; // change 1 bit in first byte
		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(new String(encrypted, UTF_8));
		});
	}

	@Test
	public void testEncryptionOfSameFilenamesWithDifferentAssociatedData() {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		final String encrypted1 = filenameCryptor.encryptFilename("test", "ad1".getBytes(UTF_8));
		final String encrypted2 = filenameCryptor.encryptFilename("test", "ad2".getBytes(UTF_8));
		Assertions.assertNotEquals(encrypted1, encrypted2);
	}

	@Test
	public void testDeterministicEncryptionOfFilenamesWithAssociatedData() throws AuthenticationFailedException {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		final String encrypted = filenameCryptor.encryptFilename("test", "ad".getBytes(UTF_8));
		final String decrypted = filenameCryptor.decryptFilename(encrypted, "ad".getBytes(UTF_8));
		Assertions.assertEquals("test", decrypted);
	}

	@Test
	public void testDeterministicEncryptionOfFilenamesWithWrongAssociatedData() {
		final byte[] keyBytes = new byte[32];
		final DestroyableSecretKey encryptionKey = new DestroyableSecretKey(keyBytes, "AES");
		final DestroyableSecretKey macKey = new DestroyableSecretKey(keyBytes, "AES");
		final FileNameCryptorImpl filenameCryptor = new FileNameCryptorImpl(encryptionKey, macKey);

		final String encrypted = filenameCryptor.encryptFilename("test", "right".getBytes(UTF_8));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			filenameCryptor.decryptFilename(encrypted, "wrong".getBytes(UTF_8));
		});
	}

}
