/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.SecureRandom;

import org.hamcrest.CoreMatchers;
import org.hamcrest.CustomTypeSafeMatcher;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CryptorProviderTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Rule
	public final ExpectedException thrown = ExpectedException.none();

	private CryptorProvider cryptorProvider;

	@Before
	public void setup() {
		cryptorProvider = new CryptorProvider(RANDOM_MOCK);
	}

	@Test
	public void testCreateNew() {
		Cryptor cryptor = cryptorProvider.createNew();
		Assert.assertNotNull(cryptor);
	}

	@Test
	public void testCreateFromKeyWithCorrectPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		Cryptor cryptor = cryptorProvider.createFromKeyFile(testMasterKey.getBytes(), "asd");
		Assert.assertNotNull(cryptor);
	}

	@Test(expected = InvalidPassphraseException.class)
	public void testCreateFromKeyWithWrongPassphrase() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
		cryptorProvider.createFromKeyFile(testMasterKey.getBytes(), "qwe");
	}

	@Test
	public void testCreateFromKeyWithWrongVaultFormat() {
		final String testMasterKey = "{\"version\":-1,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";
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
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is " + Constants.CURRENT_VAULT_VERSION) {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return Constants.CURRENT_VAULT_VERSION.equals(item.getSupportedVersion());
			}
		}));
		cryptorProvider.createFromKeyFile(testMasterKey.getBytes(), "asd");
	}

	@Test
	public void testCreateFromKeyWithMissingVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"}";
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
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is " + Constants.CURRENT_VAULT_VERSION) {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return Constants.CURRENT_VAULT_VERSION.equals(item.getSupportedVersion());
			}
		}));
		cryptorProvider.createFromKeyFile(testMasterKey.getBytes(), "asd");
	}

	@Test
	public void testCreateFromKeyWithWrongVersionMac() {
		final String testMasterKey = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLa=\"}";
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
		}, new CustomTypeSafeMatcher<UnsupportedVaultFormatException>("current version is " + Constants.CURRENT_VAULT_VERSION) {

			@Override
			protected boolean matchesSafely(UnsupportedVaultFormatException item) {
				return Constants.CURRENT_VAULT_VERSION.equals(item.getSupportedVersion());
			}
		}));
		cryptorProvider.createFromKeyFile(testMasterKey.getBytes(), "asd");
	}

}
