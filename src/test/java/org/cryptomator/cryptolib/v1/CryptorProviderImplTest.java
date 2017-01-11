/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.KeyFile;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.CustomTypeSafeMatcher;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptorProviderImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private CryptorProviderImpl cryptorProvider;

	@Before
	public void setup() {
		cryptorProvider = new CryptorProviderImpl(RANDOM_MOCK);
	}

	@Test
	public void testCreateNew() {
		CryptorImpl cryptor = cryptorProvider.createNew();
		Assert.assertNotNull(cryptor);
	}

	@Test
	public void testCreateFromKeyWithCorrectPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		CryptorImpl cryptor = cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
		Assert.assertNotNull(cryptor);
	}

	@Test(expected = InvalidPassphraseException.class)
	public void testCreateFromKeyWithWrongPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		cryptorProvider.createFromKeyFile(keyFile, "qwe", 3);
	}

	@Test
	public void testCreateFromKeyWithPepper() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"hmacMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		CryptorImpl cryptor = cryptorProvider.createFromKeyFile(keyFile, "asd", new byte[] {(byte) 0x01}, 3);
		Assert.assertNotNull(cryptor);
	}

	@Test(expected = InvalidPassphraseException.class)
	public void testCreateFromKeyWithWrongPepper() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"hmacMasterKey\":\"jkF3rc0WQsntEMlvXSLkquBLPlSYfOUDXDg90VHcj6irG4X/TOGJhA==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		cryptorProvider.createFromKeyFile(keyFile, "asd", new byte[] {(byte) 0x02}, 3);
	}

	@Test
	public void testCreateFromKeyWithWrongVaultFormat() {
		final String testMasterKey = "{\"version\":-1,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		thrown.expect(CoreMatchers.allOf(new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("isVaultOlderThanSoftware") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.isVaultOlderThanSoftware();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("not isSoftwareOlderThanVault") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return !item.isSoftwareOlderThanVault();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("detected version is -1") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getDetectedVersion().equals(-1);
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is 3") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getSupportedVersion() == 3;
			}
		}));
		cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
	}

	@Test
	public void testCreateFromKeyWithMissingVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		thrown.expect(CoreMatchers.allOf(new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("not isVaultOlderThanSoftware") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return !item.isVaultOlderThanSoftware();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("isSoftwareOlderThanVault") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.isSoftwareOlderThanVault();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("detected version is MAX INT") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getDetectedVersion().equals(Integer.MAX_VALUE);
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is 3") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getSupportedVersion() == 3;
			}
		}));
		cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
	}

	@Test
	public void testCreateFromKeyWithWrongVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLa=\"}";
		KeyFile keyFile = KeyFile.parse(testMasterKey.getBytes());
		thrown.expect(CoreMatchers.allOf(new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("not isVaultOlderThanSoftware") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return !item.isVaultOlderThanSoftware();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("isSoftwareOlderThanVault") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.isSoftwareOlderThanVault();
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("detected version is MAX INT") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getDetectedVersion().equals(Integer.MAX_VALUE);
			}
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is 3") {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return item.getSupportedVersion() == 3;
			}
		}));
		cryptorProvider.createFromKeyFile(keyFile, "asd", 3);
	}

}
