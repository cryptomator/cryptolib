package org.cryptomator.cryptolib.v1;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.PerpetualMasterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

class DirectoryContentCryptorImplTest {

	private static final SecureRandom CSPRNG = new SecureRandom();
	private static DirectoryContentCryptorImpl dirCryptor;

	@BeforeAll
	public static void setUp() {
		byte[] key = new byte[64];
		Arrays.fill(key, 0, 32, (byte) 0x55); // enc key
		Arrays.fill(key, 32, 64, (byte) 0x77); // mac key
		PerpetualMasterkey masterkey = new PerpetualMasterkey(key);
		dirCryptor = (DirectoryContentCryptorImpl) CryptorProvider.forScheme(CryptorProvider.Scheme.SIV_CTRMAC).provide(masterkey, CSPRNG).directoryContentCryptor();
	}

	@Test
	@DisplayName("encrypt and decrypt dir.c9r files")
	public void encryptAndDecryptDirectoryMetadata() {
		DirectoryMetadataImpl origMetadata = dirCryptor.newDirectoryMetadata();

		byte[] encryptedMetadata = dirCryptor.encryptDirectoryMetadata(origMetadata);
		DirectoryMetadataImpl decryptedMetadata = dirCryptor.decryptDirectoryMetadata(encryptedMetadata);

		Assertions.assertArrayEquals(origMetadata.dirId(), decryptedMetadata.dirId());
	}

	@Test
	@DisplayName("encrypt WELCOME.rtf in root dir")
	public void testEncryptReadme() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		DirectoryContentCryptor.Encrypting enc = dirCryptor.fileNameEncryptor(rootDirMetadata);
		String ciphertext = enc.encrypt("WELCOME.rtf");
		Assertions.assertEquals("4BwXESMPHMIGXeiyQifg2xBDzblPVdRuU1dy.c9r", ciphertext);
	}

	@Test
	@DisplayName("decrypt WELCOME.rtf in root dir")
	public void testDecryptReadme() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		DirectoryContentCryptor.Decrypting dec = dirCryptor.fileNameDecryptor(rootDirMetadata);
		String plaintext = dec.decrypt("4BwXESMPHMIGXeiyQifg2xBDzblPVdRuU1dy.c9r");
		Assertions.assertEquals("WELCOME.rtf", plaintext);
	}

	@Test
	@DisplayName("get root dir path")
	public void testRootDirPath() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		String path = dirCryptor.dirPath(rootDirMetadata);
		Assertions.assertEquals("d/VL/WEHT553J5DR7OZLRJAYDIWFCXZABOD", path);
	}

	@Nested
	@DisplayName("Given a specific dir.c9f file")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class WithDirectoryMetadata {

		DirectoryMetadataImpl dirC9r;
		DirectoryContentCryptor.Encrypting enc;
		DirectoryContentCryptor.Decrypting dec;

		@BeforeAll
		public void setup() {
			dirC9r = new DirectoryMetadataImpl("deadbeef-cafe-4bob-beef-decafbadface".getBytes(StandardCharsets.US_ASCII));
			enc = dirCryptor.fileNameEncryptor(dirC9r);
			dec = dirCryptor.fileNameDecryptor(dirC9r);
		}

		@DisplayName("encrypt multiple file names")
		@ParameterizedTest(name = "fileNameEncryptor.encrypt('{0}') == '{1}'")
		@CsvSource({
				"file1.txt, sL-e8HOmmqdyIJspqfB0P6zXxoBGHZw9XQ==.c9r",
				"file2.txt, hNJmLgIVcneOTeK5E-K_v3Vd9hgb2jJcQA==.c9r",
				"file3.txt, qjfr-LCwvfTDMjWmR1CwEAcM7cj-IFDVIw==.c9r",
				"file4.txt, dqL5KkgfQveDBRXl3o6FmSZ87apNzNeiDg==.c9r"
		})
		public void testBulkEncryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(ciphertext, enc.encrypt(plaintext));
		}

		@DisplayName("decrypt multiple file names")
		@ParameterizedTest(name = "fileNameDecryptor.decrypt('{1}') == '{0}'")
		@CsvSource({
				"file1.txt, sL-e8HOmmqdyIJspqfB0P6zXxoBGHZw9XQ==.c9r",
				"file2.txt, hNJmLgIVcneOTeK5E-K_v3Vd9hgb2jJcQA==.c9r",
				"file3.txt, qjfr-LCwvfTDMjWmR1CwEAcM7cj-IFDVIw==.c9r",
				"file4.txt, dqL5KkgfQveDBRXl3o6FmSZ87apNzNeiDg==.c9r"
		})
		public void testBulkDecryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(plaintext, dec.decrypt(ciphertext));
		}

		@Test
		@DisplayName("decrypt file with invalid extension")
		public void testDecryptMalformed1() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				dec.decrypt("sL-e8HOmmqdyIJspqfB0P6zXxoBGHZw9XQ==.INVALID");
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic ciphertext")
		public void testDecryptMalformed2() {
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				dec.decrypt("INVALID-e8HOmmqdyIJspqfB0P6zXxoBGHZw9XQ==.c9r.c9r");
			});
		}

		@Test
		@DisplayName("decrypt file with incorrect dirId")
		public void testDecryptMalformed3() {
			DirectoryMetadataImpl differentDirId = new DirectoryMetadataImpl("deadbeef-cafe-4bob-beef-badbadbadbad".getBytes(StandardCharsets.US_ASCII));
			DirectoryContentCryptor.Decrypting differentDirIdDec = dirCryptor.fileNameDecryptor(differentDirId);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				differentDirIdDec.decrypt("sL-e8HOmmqdyIJspqfB0P6zXxoBGHZw9XQ==.c9r");
			});
		}

	}

}