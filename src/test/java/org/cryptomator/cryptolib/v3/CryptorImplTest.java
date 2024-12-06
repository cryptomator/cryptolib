package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class CryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(-1540072521, Base64.getDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU="));
	private static final byte[] KDF_SALT =  Base64.getDecoder().decode("HE4OP+2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=");

	private UVFMasterkey masterkey;

	@BeforeEach
	public void setup() {
		 masterkey = new UVFMasterkey(SEEDS, KDF_SALT, -1540072521, -1540072521);
	}

	@Test
	public void testGetFileContentCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertInstanceOf(FileContentCryptorImpl.class, cryptor.fileContentCryptor());
		}
	}

	@Test
	public void testGetFileHeaderCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertInstanceOf(FileHeaderCryptorImpl.class, cryptor.fileHeaderCryptor());
		}
	}

	@Test
	public void testGetFileNameCryptor() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertThrows(UnsupportedOperationException.class, cryptor::fileNameCryptor);
		}
	}

	@Test
	public void testGetFileNameCryptorWithInvalidRevisions() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> cryptor.fileNameCryptor(0xBAD5EED));
		}
	}

	@Test
	public void testGetFileNameCryptorWithCorrectRevisions() {
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertInstanceOf(FileNameCryptorImpl.class, cryptor.fileNameCryptor(-1540072521));
		}
	}

	@Test
	public void testExplicitDestruction() {
		UVFMasterkey masterkey = Mockito.mock(UVFMasterkey.class);
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			cryptor.destroy();
			Mockito.verify(masterkey).destroy();
			Mockito.when(masterkey.isDestroyed()).thenReturn(true);
			Assertions.assertTrue(cryptor.isDestroyed());
		}
	}

	@Test
	public void testImplicitDestruction() {
		UVFMasterkey masterkey = Mockito.mock(UVFMasterkey.class);
		try (CryptorImpl cryptor = new CryptorImpl(masterkey, RANDOM_MOCK)) {
			Assertions.assertFalse(cryptor.isDestroyed());
		}
		Mockito.verify(masterkey).destroy();
	}

}
