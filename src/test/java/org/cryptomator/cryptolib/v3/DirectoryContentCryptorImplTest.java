package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.DirectoryContentCryptor;
import org.cryptomator.cryptolib.api.DirectoryMetadata;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

class DirectoryContentCryptorImplTest {

	private static final SecureRandom CSPRNG = new SecureRandom();
	private static UVFMasterkey masterkey;
	private static DirectoryContentCryptorImpl dirCryptor;

	// root dir.uvf and symlink.uvf (target "../target") for the spec's example payload
	private static final String ROOT_DIR_UVF = "dXZmAQ1N5H29YIjDh1UAzXRxhQd1DvVThqIWmBy8CFAJ7wOqKnQZCU9LmQ27cmRfzqJ1EWFqkQ0E70rtLN/2oZRQFPHCLK3+oytYu8EW8YLWR1g+0m+P1ql5sDKpJ6Hn49oaALdgAV8llw4+tZ0i5DjzgvTdJsAxprgWe3bgBgc=";
	private static final String SYMLINK_UVF = "dXZmAavGTKuhSpspG9vYfPWIe/GJOXW+rLPMcyzaiTPS4rx4k6Qvl1UlJFOL5Yr/XM8PpbJA5f2/JNvRYpc+DAjmaoAjb6B9hb9Ak8bYBk3RCCVwpo0zSapxxnJnh+H40GWMDSBDgE1V";

	@BeforeAll
	public static void setUp() {
		// example payload from the UVF spec, see UVFMasterkeyTest:
		String json = "{\n" +
				"    \"fileFormat\": \"AES-256-GCM-32k\",\n" +
				"    \"nameFormat\": \"AES-SIV-512-B64URL\",\n" +
				"    \"seeds\": {\n" +
				"        \"DU3kfQ\": \"ypeBEsobvcr6wjGzmiPcTaeG7_gUfE5yuYB3ha_uSLs\",\n" +
				"        \"YuRlmw\": \"PiPoFgA5WUoziU9lZOGxNIu9egCI1CxKy3PurtWcAJ0\",\n" +
				"        \"q8ZMqw\": \"Ln0sA6lQeuJl7PW1NWiFpTOTogKdJBOUmXJloaJa78Y\"\n" +
				"    },\n" +
				"    \"initialSeed\": \"DU3kfQ\",\n" +
				"    \"latestSeed\": \"q8ZMqw\",\n" +
				"    \"kdf\": \"HKDF-SHA512\",\n" +
				"    \"kdfSalt\": \"NIlr89R7FhochyP4yuXZmDqCnQ0dBB3UZ2D-6oiIjr8\",\n" +
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

		Assertions.assertEquals(128, encryptedMetadata.length);
		Assertions.assertEquals(origMetadata.seedId(), decryptedMetadata.seedId());
		Assertions.assertArrayEquals(origMetadata.dirId(), decryptedMetadata.dirId());
	}

	@Test
	@DisplayName("decrypt root dir.uvf")
	public void testDecryptRootDirectoryMetadata() {
		DirectoryMetadataImpl decryptedMetadata = dirCryptor.decryptDirectoryMetadata(Base64.getDecoder().decode(ROOT_DIR_UVF));

		Assertions.assertEquals(masterkey.firstRevision(), decryptedMetadata.seedId());
		Assertions.assertArrayEquals(masterkey.rootDirId(), decryptedMetadata.dirId());
	}

	@DisplayName("decrypt dir.uvf of invalid length")
	@ParameterizedTest(name = "length {0}")
	@ValueSource(ints = {0, 127, 129})
	public void testDecryptDirectoryMetadataOfInvalidLength(int length) {
		byte[] ciphertext = Arrays.copyOf(Base64.getDecoder().decode(ROOT_DIR_UVF), length);
		Assertions.assertThrows(IllegalArgumentException.class, () -> dirCryptor.decryptDirectoryMetadata(ciphertext));
	}

	@Test
	@DisplayName("decrypt symlink.uvf as dir.uvf (wrong node type)")
	public void testDecryptSymlinkAsDirectoryMetadata() {
		byte[] ciphertext = dirCryptor.encryptSymlinkTarget("0123456789abcdef0123456789abcdef"); // 32 byte target, so the file has the size of a dir.uvf
		Assertions.assertEquals(128, ciphertext.length);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> dirCryptor.decryptDirectoryMetadata(ciphertext));
	}

	@Test
	@DisplayName("encrypt and decrypt symlink.uvf files")
	public void encryptAndDecryptSymlinkTarget() {
		byte[] ciphertext = dirCryptor.encryptSymlinkTarget("../target");

		Assertions.assertEquals(68 + 12 + 9 + 16, ciphertext.length);
		Assertions.assertArrayEquals(new byte[]{'u', 'v', 'f', 0x01}, Arrays.copyOf(ciphertext, 4));
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("q8ZMqw"), Arrays.copyOfRange(ciphertext, 4, 8), "latest seed");
		Assertions.assertEquals("../target", dirCryptor.decryptSymlinkTarget(ciphertext));
	}

	@Test
	@DisplayName("decrypt symlink.uvf")
	public void testDecryptSymlinkTarget() {
		Assertions.assertEquals("../target", dirCryptor.decryptSymlinkTarget(Base64.getDecoder().decode(SYMLINK_UVF)));
	}

	@Test
	@DisplayName("decrypt dir.uvf as symlink.uvf (wrong node type)")
	public void testDecryptDirectoryMetadataAsSymlink() {
		byte[] ciphertext = Base64.getDecoder().decode(ROOT_DIR_UVF);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> dirCryptor.decryptSymlinkTarget(ciphertext));
	}

	@Test
	@DisplayName("symlink targets are NFC-normalized")
	public void testSymlinkTargetNormalization() {
		byte[] ciphertext = dirCryptor.encryptSymlinkTarget("é"); // NFD
		Assertions.assertEquals("é", dirCryptor.decryptSymlinkTarget(ciphertext)); // NFC
	}

	@Test
	@DisplayName("encrypt WELCOME.rtf in root dir")
	public void testEncryptReadme() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		DirectoryContentCryptor.Encrypting enc = dirCryptor.fileNameEncryptor(rootDirMetadata);
		String ciphertext = enc.encrypt("WELCOME.rtf");
		Assertions.assertEquals("Dx1binBPsg_KNby6KFD_2k3vZHPgo39rg4ks.uvf", ciphertext);
	}

	@Test
	@DisplayName("decrypt WELCOME.rtf in root dir")
	public void testDecryptReadme() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		DirectoryContentCryptor.Decrypting dec = dirCryptor.fileNameDecryptor(rootDirMetadata);
		String plaintext = dec.decrypt("Dx1binBPsg_KNby6KFD_2k3vZHPgo39rg4ks.uvf");
		Assertions.assertEquals("WELCOME.rtf", plaintext);
	}

	@Test
	@DisplayName("get root dir path")
	public void testRootDirPath() {
		DirectoryMetadata rootDirMetadata = dirCryptor.rootDirectoryMetadata();
		String path = dirCryptor.dirPath(rootDirMetadata);
		Assertions.assertEquals("d/RZ/K7ZH7KBXULNEKBMGX3CU42PGUIAIX4", path);
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
				"file1.txt, NIWamUJBS3u619f3yKOWlT2q_raURsHXhg.uvf",
				"file2.txt, _EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg.uvf",
				"file3.txt, dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw.uvf",
				"file4.txt, 2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg.uvf"
		})
		public void testBulkEncryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(ciphertext, enc.encrypt(plaintext));
		}

		@DisplayName("decrypt multiple file names")
		@ParameterizedTest(name = "fileNameDecryptor.decrypt('{1}') == '{0}'")
		@CsvSource({
				"file1.txt, NIWamUJBS3u619f3yKOWlT2q_raURsHXhg.uvf",
				"file2.txt, _EWTVc9qooJQyk-P9pwQkvSu9mFb0UWNeg.uvf",
				"file3.txt, dunZsv8VRuh81R-u6pioPx2DWeQAU0nLfw.uvf",
				"file4.txt, 2-clI661p9TBSzC2IJjvBF3ehaKas5Vqxg.uvf"
		})
		public void testBulkDecryption(String plaintext, String ciphertext) {
			Assertions.assertEquals(plaintext, dec.decrypt(ciphertext));
		}

		@Test
		@DisplayName("decrypt file with invalid extension")
		public void testDecryptMalformed1() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				dec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg.INVALID");
			});
		}

		@Test
		@DisplayName("decrypt file with unauthentic ciphertext")
		public void testDecryptMalformed2() {
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				dec.decrypt("INVALIDamUJBS3u619f3yKOWlT2q_raURsHXhg.uvf");
			});
		}

		@Test
		@DisplayName("decrypt file with incorrect seed")
		public void testDecryptMalformed3() {
			DirectoryMetadataImpl differentRevision = new DirectoryMetadataImpl(masterkey.firstRevision(), new byte[32]);
			DirectoryContentCryptor.Decrypting differentRevisionDec = dirCryptor.fileNameDecryptor(differentRevision);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				differentRevisionDec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg.uvf");
			});
		}

		@Test
		@DisplayName("decrypt file with incorrect dirId")
		public void testDecryptMalformed4() {
			DirectoryMetadataImpl differentDirId = new DirectoryMetadataImpl(masterkey.firstRevision(), new byte[]{(byte) 0xDE, (byte) 0x0AD});
			DirectoryContentCryptor.Decrypting differentDirIdDec = dirCryptor.fileNameDecryptor(differentDirId);
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				differentDirIdDec.decrypt("NIWamUJBS3u619f3yKOWlT2q_raURsHXhg.uvf");
			});
		}

		@DisplayName("decrypt non-canonical ciphertext names")
		@ParameterizedTest(name = "{1}: {0}")
		@CsvSource({
				"NIWamUJBS3u619f3yKOWlT2q_raURsHXhg==.uvf, padding",
				"NIWamUJBS3u619f3yKOWlT2q_raURsHXhh.uvf, non-zero trailing bits",
				"NIWamUJBS3u619f3yKOWlT2q+raURsHXhg.uvf, standard base64 alphabet",
				"NIWamUJBS3u619f3yKOWlT2q_raURsHXh.uvf, invalid length",
		})
		public void testDecryptNonCanonical(String ciphertext, String reason) {
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				dec.decrypt(ciphertext);
			});
		}

		@DisplayName("reject invalid decrypted names")
		@ParameterizedTest(name = "'{0}'")
		@ValueSource(strings = {"", ".", "..", "a/b", "/", "a\u0000b"})
		public void testRejectInvalidCleartextNames(String name) {
			String ciphertext = enc.encrypt(name); // another client may have stored anything
			Assertions.assertThrows(AuthenticationFailedException.class, () -> {
				dec.decrypt(ciphertext);
			});
		}

		@DisplayName("accept unusual but valid decrypted names")
		@ParameterizedTest(name = "'{0}'")
		@ValueSource(strings = {"...", ".hidden", "a b", "a\\b", "a:b"})
		public void testAcceptValidCleartextNames(String name) {
			Assertions.assertEquals(name, dec.decrypt(enc.encrypt(name)));
		}

	}

}
