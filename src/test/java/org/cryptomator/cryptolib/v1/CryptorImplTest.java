/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

public class CryptorImplTest {

	private static final Charset UTF_8 = Charset.forName("UTF-8");
	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private SecretKey encKey;
	private SecretKey macKey;

	@BeforeEach
	public void setup() {
		encKey = new SecretKeySpec(new byte[32], "AES");
		macKey = new SecretKeySpec(new byte[32], "HmacSHA256");
	}

	@Test
	public void testWriteKeysToMasterkeyFile() {
		final byte[] serialized;
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			serialized = cryptor.writeKeysToMasterkeyFile("asd", 3).serialize();
		}
		String serializedStr = new String(serialized, UTF_8);
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"version\": 3"));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptSalt\": \"AAAAAAAAAAA=\""));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptCostParam\": 32768"));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptBlockSize\": 8"));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"primaryMasterKey\": \"bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==\""));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"hmacMasterKey\": \"bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==\""));
		MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"versionMac\": \"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\""));
	}

	@Test
	public void testWriteKeysToMasterkeyFileWithPepper() {
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			byte[] serialized1 = cryptor.writeKeysToMasterkeyFile("asd", new byte[] {(byte) 0x01}, 3).serialize();
			byte[] serialized2 = cryptor.writeKeysToMasterkeyFile("asd", new byte[] {(byte) 0x02}, 3).serialize();
			MatcherAssert.assertThat(serialized1, not(equalTo(serialized2)));
		}
	}
	
	@Test
	public void testGetRawKey() {
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			byte[] rawKey = cryptor.getRawKey();
			Assertions.assertArrayEquals(Arrays.copyOf(rawKey, Constants.KEY_LEN_BYTES), encKey.getEncoded());
			Assertions.assertArrayEquals(Arrays.copyOfRange(rawKey, Constants.KEY_LEN_BYTES, 2*Constants.KEY_LEN_BYTES), macKey.getEncoded());
		}
	}

	@Test
	public void testGetFileContentCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileContentCryptor(), CoreMatchers.instanceOf(FileContentCryptorImpl.class));
		}
	}

	@Test
	public void testGetFileHeaderCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileHeaderCryptor(), CoreMatchers.instanceOf(FileHeaderCryptorImpl.class));
		}
	}

	@Test
	public void testGetFileNameCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			MatcherAssert.assertThat(cryptor.fileNameCryptor(), CoreMatchers.instanceOf(FileNameCryptorImpl.class));
		}
	}

	@Test
	public void testExplicitDestruction() throws DestroyFailedException {
		DestroyableSecretKey encKey = Mockito.mock(DestroyableSecretKey.class);
		DestroyableSecretKey macKey = Mockito.mock(DestroyableSecretKey.class);
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			cryptor.destroy();
			Mockito.verify(encKey).destroy();
			Mockito.verify(macKey).destroy();
			Mockito.when(encKey.isDestroyed()).thenReturn(true);
			Mockito.when(macKey.isDestroyed()).thenReturn(true);
			Assertions.assertTrue(cryptor.isDestroyed());
		}
	}

	@Test
	public void testImplicitDestruction() throws DestroyFailedException {
		DestroyableSecretKey encKey = Mockito.mock(DestroyableSecretKey.class);
		DestroyableSecretKey macKey = Mockito.mock(DestroyableSecretKey.class);
		try (CryptorImpl cryptor = new CryptorImpl(encKey, macKey, RANDOM_MOCK)) {
			Assertions.assertFalse(cryptor.isDestroyed());
		}
		Mockito.verify(encKey).destroy();
		Mockito.verify(macKey).destroy();
	}

	private interface DestroyableSecretKey extends SecretKey, Destroyable {
		// In Java7 SecretKey doesn't implement Destroyable...
	}

}
