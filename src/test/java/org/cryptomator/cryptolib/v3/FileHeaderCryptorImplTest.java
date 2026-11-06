package org.cryptomator.cryptolib.v3;

import com.google.common.io.BaseEncoding;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.api.UVFMasterkey;
import org.cryptomator.cryptolib.common.CipherSupplier;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.cryptomator.cryptolib.common.GcmTestHelper;
import org.cryptomator.cryptolib.common.ObjectPool;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final byte[] SEED = Base64.getUrlDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU");
	private static final int SEED_ID = 1925996179; // derived from SEED and KDF_SALT, see UVFMasterkeyTest
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(SEED_ID, SEED);
	private static final byte[] KDF_SALT = Base64.getUrlDecoder().decode("HE4OP-2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY");
	private static final UVFMasterkey MASTERKEY = new UVFMasterkey(SEEDS, KDF_SALT, SEED_ID, SEED_ID);

	// header with all-zero nonce and content key, encrypted under the fileHeader context
	private static final String FILE_HEADER = "dXZmAXLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0=";

	private FileHeaderCryptorImpl headerCryptor;

	@BeforeEach
	public void setup() {
		headerCryptor = new FileHeaderCryptorImpl(MASTERKEY, RANDOM_MOCK, SEED_ID);

		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
				cipher.get();
			}
		});
	}

	@Test
	public void testHeaderSize() {
		Assertions.assertEquals(68, FileHeaderImpl.SIZE);
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.headerSize());
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.encryptHeader(headerCryptor.create()).limit());
	}

	@Test
	public void testSubkeyGeneration() {
		DestroyableSecretKey subkey = MASTERKEY.subKey(SEED_ID, 32, "fileHeader".getBytes(), "AES");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("PwnW2t_pK9dmzc-GTLdBSaB8ilcwsTq4sYOeiyo3cpU"), subkey.getEncoded());
	}

	@Test
	public void testEncryption() {
		DestroyableSecretKey contentKey = new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES");
		FileHeader header = new FileHeaderImpl(SEED_ID, new byte[FileHeaderImpl.NONCE_LEN], contentKey);

		ByteBuffer ciphertext = headerCryptor.encryptHeader(header);

		Assertions.assertArrayEquals(Base64.getDecoder().decode(FILE_HEADER), ciphertext.array());
		Assertions.assertArrayEquals(new byte[]{'u', 'v', 'f', 0x01}, java.util.Arrays.copyOf(ciphertext.array(), 4), "magic bytes and spec version 1");
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode("csxekw"), java.util.Arrays.copyOfRange(ciphertext.array(), 4, 8), "big-endian seed ID");
	}

	@DisplayName("encrypt header per node type")
	@ParameterizedTest(name = "{0}")
	@CsvSource({
			"fileHeader, dXZmAXLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0=",
			"dirHeader, dXZmAXLMXpMAAAAAAAAAAAAAAACSMEIU8Way2v06JUW8L7tOayyrblFXlqVcGnel82E3jJWeBYo6jbNTMVq3RSquBjM=",
			"symlinkHeader, dXZmAXLMXpMAAAAAAAAAAAAAAAB7eLzxU/8GNgNM+Zx4MhlIkyfCOFIUMKMfqGgqubqFMm8xi9X3wC8zTkDIkIwF8V4=",
	})
	public void testEncryptionPerNodeType(String context, String expected) throws AuthenticationFailedException {
		FileHeaderCryptorImpl cryptor = new FileHeaderCryptorImpl(MASTERKEY, RANDOM_MOCK, SEED_ID, context.getBytes());
		DestroyableSecretKey contentKey = new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES");
		FileHeader header = new FileHeaderImpl(SEED_ID, new byte[FileHeaderImpl.NONCE_LEN], contentKey);

		ByteBuffer ciphertext = cryptor.encryptHeader(header);

		Assertions.assertArrayEquals(Base64.getDecoder().decode(expected), ciphertext.array());
		FileHeaderImpl decrypted = cryptor.decryptHeader(ciphertext);
		Assertions.assertArrayEquals(new byte[FileHeaderImpl.CONTENT_KEY_LEN], decrypted.getContentKey().getEncoded());
	}

	@DisplayName("decrypt header of a different node type")
	@ParameterizedTest(name = "{0} header decrypted with fileHeader context")
	@CsvSource({
			"dirHeader, dXZmAXLMXpMAAAAAAAAAAAAAAACSMEIU8Way2v06JUW8L7tOayyrblFXlqVcGnel82E3jJWeBYo6jbNTMVq3RSquBjM=",
			"symlinkHeader, dXZmAXLMXpMAAAAAAAAAAAAAAAB7eLzxU/8GNgNM+Zx4MhlIkyfCOFIUMKMfqGgqubqFMm8xi9X3wC8zTkDIkIwF8V4=",
	})
	public void testDecryptionWithWrongNodeType(String context, String ciphertext) {
		ByteBuffer buf = ByteBuffer.wrap(Base64.getDecoder().decode(ciphertext));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(buf);
		});
	}

	@Test
	public void testDecryption() throws AuthenticationFailedException {
		byte[] ciphertext = BaseEncoding.base64().decode(FILE_HEADER);
		FileHeaderImpl header = headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
		Assertions.assertEquals(SEED_ID, header.getSeedId());
		Assertions.assertArrayEquals(new byte[FileHeaderImpl.NONCE_LEN], header.getNonce());
		Assertions.assertArrayEquals(new byte[FileHeaderImpl.CONTENT_KEY_LEN], header.getContentKey().getEncoded());
	}

	@Test
	public void testDecryptionWithTooShortHeader() {
		ByteBuffer ciphertext = ByteBuffer.allocate(7);

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	@DisplayName("decrypt header with wrong magic bytes")
	public void testDecryptionWithInvalidMagicBytes() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("eHZmAXLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0="));

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
		Assertions.assertEquals("Not a UVF file", e.getMessage());
	}

	@Test
	@DisplayName("decrypt header with unsupported spec version")
	public void testDecryptionWithUnsupportedVersion() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAnLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0="));

		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
		Assertions.assertEquals("Unsupported UVF spec version: 2", e.getMessage());
	}

	@Test
	@DisplayName("decrypt header with unknown seed ID")
	public void testDecryptionWithUnknownSeed() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAXLMXpIAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0="));

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidTag() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAXLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGaw="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidCiphertext() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAXLMXpMAAAAAAAAAAAAAAAA/UGgFA8QGho7E1ATsHWyZIVFqabbGJ/TCwvp3StG0JU5E5VDk0cwt/HOJ8RAaGa0="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

}
