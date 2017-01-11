/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

import java.nio.charset.Charset;
import java.security.SecureRandom;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class CryptorImplTest {

	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private SecretKey encKey;
	private SecretKey macKey;

	@Before
	public void setup() {
		encKey = new SecretKeySpec(new byte[32], "AES");
		macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
	}

	@Test
	public void testWriteKeysToMasterkeyFile() {
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		final byte[] serialized = cryptor.writeKeysToMasterkeyFile("asd", 3).serialize();
		String serializedStr = new String(serialized, UTF_8);
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"version\": 3"));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptSalt\": \"AAAAAAAAAAA=\""));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptCostParam\": 16384"));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptBlockSize\": 8"));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"primaryMasterKey\": \"BJPIq5pvhN24iDtPJLMFPLaVJWdGog9k4n0P03j4ru+ivbWY9OaRGQ==\""));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"hmacMasterKey\": \"BJPIq5pvhN24iDtPJLMFPLaVJWdGog9k4n0P03j4ru+ivbWY9OaRGQ==\""));
		Assert.assertThat(serializedStr, CoreMatchers.containsString("\"versionMac\": \"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\""));
	}

	@Test
	public void testWriteKeysToMasterkeyFileWithPepper() {
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		final byte[] serialized1 = cryptor.writeKeysToMasterkeyFile("asd", new byte[] {(byte) 0x01}, 3).serialize();
		final byte[] serialized2 = cryptor.writeKeysToMasterkeyFile("asd", new byte[] {(byte) 0x02}, 3).serialize();
		Assert.assertThat(serialized1, not(equalTo(serialized2)));
		System.out.println(new String(serialized1));
		System.out.println(new String(serialized2));
	}

	@Test
	public void testGetFileContentCryptor() {
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		Assert.assertThat(cryptor.fileContentCryptor(), CoreMatchers.instanceOf(FileContentCryptorImpl.class));
	}

	@Test
	public void testGetFileHeaderCryptor() {
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		Assert.assertThat(cryptor.fileHeaderCryptor(), CoreMatchers.instanceOf(FileHeaderCryptorImpl.class));
	}

	@Test
	public void testGetFileNameCryptor() {
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		Assert.assertThat(cryptor.fileNameCryptor(), CoreMatchers.instanceOf(FileNameCryptorImpl.class));
	}

	@Test
	public void testDestruction() throws DestroyFailedException {
		DestroyableSecretKey encKey = Mockito.mock(DestroyableSecretKey.class);
		DestroyableSecretKey macKey = Mockito.mock(DestroyableSecretKey.class);
		final CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK);
		cryptor.destroy();
		Mockito.verify(encKey).destroy();
		Mockito.verify(macKey).destroy();
		Mockito.when(encKey.isDestroyed()).thenReturn(true);
		Mockito.when(macKey.isDestroyed()).thenReturn(true);
		Assert.assertTrue(cryptor.isDestroyed());
	}

	private static interface DestroyableSecretKey extends SecretKey, Destroyable {
		// In Java7 SecretKey doesn't implement Destroyable...
	}

}
