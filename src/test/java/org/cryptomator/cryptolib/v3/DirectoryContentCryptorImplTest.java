package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.SecureRandom;

class DirectoryContentCryptorImplTest {

	private static final SecureRandom CSPRNG = new SecureRandom();
	private static UVFMasterkey masterkey;
	private static DirectoryContentCryptorImpl dirCryptor;

	@BeforeAll
	public static void setUp() {
		// copied from UVFMasterkeyTest:
		String json = "{\n" +
				"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
				"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
				"    \"seeds\": {\n" +
				"        \"HDm38g\": \"ypeBEsobvcr6wjGzmiPcTaeG7/gUfE5yuYB3ha/uSLs=\",\n" +
				"        \"gBryKw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0=\",\n" +
				"        \"QBsJFg\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y=\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"HDm38i\",\n" +
				"    \"latestSeed\": \"QBsJFo\",\n" +
				"    \"kdf\": \"HKDF-SHA512\",\n" +
				"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D+6oiIjr8=\",\n" +
				"    \"org.example.customfield\": 42\n" +
				"}";
		masterkey = UVFMasterkey.fromDecryptedPayload(json);
		dirCryptor = (DirectoryContentCryptorImpl) CryptorProvider.forScheme(CryptorProvider.Scheme.UVF_DRAFT).provide(masterkey, CSPRNG).directoryContentCryptor();
	}

	@Test
	@DisplayName("encrypt and decrypt dir.uvf files")
	public void encryptAndDecryptDirectoryMetadata() {
		DirectoryMetadataImpl origMetadata = dirCryptor.newDirectoryMetadata();

		byte[] encryptedMetadata = dirCryptor.encryptDirectoryMetadata(origMetadata);
		DirectoryMetadataImpl decryptedMetadata = dirCryptor.decryptDirectoryMetadata(encryptedMetadata);

		Assertions.assertEquals(origMetadata.seedId(), decryptedMetadata.seedId());
		Assertions.assertArrayEquals(origMetadata.dirId(), decryptedMetadata.dirId());
	}

	@Nested
	@DisplayName("Given a specific dir.uvf file")
	@TestInstance(TestInstance.Lifecycle.PER_CLASS)
	class WithDirectoryMetadata {

		DirectoryMetadataImpl dirUvf;
		DirectoryContentCryptor.Encrypting enc;
		DirectoryContentCryptor.Decrypting dec;

		@BeforeAll
		public void setup() {
			dirUvf = new DirectoryMetadataImpl(masterkey.currentRevision(), new byte[32]);
			enc = dirCryptor.fileNameEncryptor(dirUvf);
			dec = dirCryptor.fileNameDecryptor(dirUvf);
		}

		@DisplayName("encrypt multiple file names")
		@ParameterizedTest(name = "fileNameEncryptor.encrypt('{0}') == '{1}'")
		@CsvSource({
				"file1.txt, NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf",
				"file2.txt, _EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg==.uvf",
				"file3.txt, dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw==.uvf",
				"file4.txt, 2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg==.uvf"
		})
		public void testBulkEncryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(ciphertext, enc.encrypt(plaintext));
		}

		@DisplayName("decrypt multiple file names")
		@ParameterizedTest(name = "fileNameDecryptor.decrypt('{1}') == '{0}'")
		@CsvSource({
				"file1.txt, NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf",
				"file2.txt, _EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg==.uvf",
				"file3.txt, dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw==.uvf",
				"file4.txt, 2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg==.uvf"
		})
		public void testBulkDecryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(plaintext, dec.decrypt(ciphertext));
		}

		@Test
		@DisplayName("decrypt file with invalid extension")
		public void testDecryptMalformed1() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				dec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.INVALID");
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic ciphertext")
		public void testDecryptMalformed2() {
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				dec.decrypt("INVALIDamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
			});
		}

		@Test
		@DisplayName("decrypt file with incorrect seed")
		public void testDecryptMalformed3() {
			DirectoryMetadataImpl differentRevision = new DirectoryMetadataImpl(masterkey.firstRevision(), new byte[32]);
			DirectoryContentCryptor.Decrypting differentRevisionDec = dirCryptor.fileNameDecryptor(differentRevision);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				differentRevisionDec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
			});
		}

		@Test
		@DisplayName("decrypt file with incorrect dirId")
		public void testDecryptMalformed4() {
			DirectoryMetadataImpl differentDirId = new DirectoryMetadataImpl(masterkey.firstRevision(), new byte[]{(byte) 0xDE, (byte) 0x0AD});
			DirectoryContentCryptor.Decrypting differentDirIdDec = dirCryptor.fileNameDecryptor(differentDirId);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				differentDirIdDec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf");
			});
		}

	}

}