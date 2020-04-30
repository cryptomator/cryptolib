/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

public class CryptorProviderImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	private CryptorProviderImpl cryptorProvider;

	@BeforeEach
	public void setup() {
		cryptorProvider = new CryptorProviderImpl(RANDOM_MOCK);
	}

	@Test
	public void testCreateNew() {
		CryptorImpl cryptor = cryptorProvider.createNew();
		Assertions.assertNotNull(cryptor);
	}

	@ParameterizedTest
	@MethodSource("create64RandomBytes")
	public void testCreateFromRawKey(byte[] rawKey) {
		CryptorImpl cryptor = cryptorProvider.createFromRawKey(rawKey);
		Assertions.assertNotNull(cryptor);
		Assertions.assertArrayEquals(rawKey, cryptor.getRawKey());
	}

	static Stream<Arguments> create64RandomBytes() {
		Random rnd = new Random(42l);
		return Stream.generate(() -> {
			byte[] bytes = new byte[64];
			rnd.nextBytes(bytes);
			return Arguments.of(bytes);
		}).limit(10);
	}

	@Test
	public void testCreateFromInvalidRawKey() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			cryptorProvider.createFromRawKey(new byte[3]);
		});
	}

	@Test
	public void testCreateFromKeyWithCorrectPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		CryptorImpl cryptor = cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
		Assertions.assertNotNull(cryptor);
	}

	@Test
	public void testCreateFromKeyWithWrongPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		Assertions.assertThrows(InvalidPassphraseException.class, () -> {
			cryptorProvider.createFromKeyFile(keyFile, "qwe", 3);
		});
	}

	@Test
	public void testCreateFromKeyWithPepper() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"hmacMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		CryptorImpl cryptor = cryptorProvider.createFromKeyFile(keyFile, "asd", new byte[]{(byte) 0x01}, 3);
		Assertions.assertNotNull(cryptor);
	}

	@Test
	public void testCreateFromKeyWithWrongPepper() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"hmacMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		Assertions.assertThrows(InvalidPassphraseException.class, () -> {
			cryptorProvider.createFromKeyFile(keyFile, "asd", new byte[]{(byte) 0x02}, 3);
		});
	}

	@Test
	public void testCreateFromKeyWithWrongVaultFormat() {
		final String testMasterKey = "{\"version\":-1,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		UnsupportedVaultFormatException exception = Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> {
			cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
		});
		Assertions.assertTrue(exception.isVaultOlderThanSoftware());
		Assertions.assertFalse(exception.isSoftwareOlderThanVault());
		Assertions.assertEquals(-1, exception.getDetectedVersion());
		Assertions.assertEquals(3, exception.getSupportedVersion());
	}

	@Test
	public void testCreateFromKeyWithMissingVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		UnsupportedVaultFormatException exception = Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> {
			cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
		});
		Assertions.assertFalse(exception.isVaultOlderThanSoftware());
		Assertions.assertTrue(exception.isSoftwareOlderThanVault());
		Assertions.assertEquals(Integer.MAX_VALUE, exception.getDetectedVersion());
		Assertions.assertEquals(3, exception.getSupportedVersion());
	}

	@Test
	public void testCreateFromKeyWithWrongVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLa=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		UnsupportedVaultFormatException exception = Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> {
			cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
		});
		Assertions.assertFalse(exception.isVaultOlderThanSoftware());
		Assertions.assertTrue(exception.isSoftwareOlderThanVault());
		Assertions.assertEquals(Integer.MAX_VALUE, exception.getDetectedVersion());
		Assertions.assertEquals(3, exception.getSupportedVersion());
	}

}
