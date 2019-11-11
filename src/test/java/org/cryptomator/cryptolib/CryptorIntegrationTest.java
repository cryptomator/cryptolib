package org.cryptomator.cryptolib;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeaderCryptor;
import org.cryptomator.cryptolib.api.FileNameCryptor;
import org.cryptomator.cryptolib.api.KeyFile;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Arrays;

class CryptorIntegrationTest {

	private SecureRandom seeder;
	private CryptorProvider cryptorProvider;

	@BeforeEach
	public void setup() {
		seeder = Mockito.mock(SecureRandom.class);
		Mockito.when(seeder.generateSeed(Mockito.anyInt())).then(invocation -> {
			int numBytes = invocation.getArgument(0);
			return new byte[numBytes];
		});
		cryptorProvider = Cryptors.version1(seeder);
		Assertions.assertNotNull(cryptorProvider);
	}

	@Test
	public void testCreateCryptor() {
		Cryptor cryptor = cryptorProvider.createNew();
		Assertions.assertNotNull(cryptor);
		FileContentCryptor fileContentCryptor = cryptor.fileContentCryptor();
		FileHeaderCryptor fileHeaderCryptor = cryptor.fileHeaderCryptor();
		FileNameCryptor fileNameCryptor = cryptor.fileNameCryptor();
		Assertions.assertNotNull(fileContentCryptor);
		Assertions.assertNotNull(fileHeaderCryptor);
		Assertions.assertNotNull(fileNameCryptor);
	}
	
	@Nested
	class WithWrittenMasterkeyFile {
		
		private Cryptor cryptor;
		private byte[] pepper;
		private CharSequence passphrase;
		private byte[] masterkey;
		
		@BeforeEach
		public void setup() {
			cryptor = cryptorProvider.createNew();
			pepper = new byte[0];
			passphrase = "password";
			masterkey = cryptor.writeKeysToMasterkeyFile(passphrase, 42).serialize();
		}
		
		@Test
		public void changePassword() {
			byte[] newMasterkey = Cryptors.changePassphrase(cryptorProvider, masterkey, "password", "betterPassw0rd!");
			Assertions.assertFalse(Arrays.equals(masterkey, newMasterkey));
			
			Cryptor newCryptor = cryptorProvider.createFromKeyFile(KeyFile.parse(newMasterkey), "betterPassw0rd!", 42);
			Assertions.assertNotNull(newCryptor);
			Assertions.assertNotSame(cryptor, newCryptor);
		}
		
		@Test
		public void testExportRawKey() {
			byte[] rawKey = Cryptors.exportRawKey(cryptorProvider, masterkey, pepper, passphrase);
			Assertions.assertNotNull(rawKey);
		}
		
		@Nested
		class WithExportedRawKey {

			byte[] rawKey;

			@BeforeEach
			public void setup() {
				rawKey = Cryptors.exportRawKey(cryptorProvider, masterkey, pepper, passphrase);
			}
			
			@Test
			public void testRestoreRawKey() {
				byte[] newMasterkey = Cryptors.restoreRawKey(cryptorProvider, rawKey, pepper, passphrase, 42);
				Assertions.assertFalse(Arrays.equals(masterkey, newMasterkey));
			}
			
		}
		
	}
	
}
