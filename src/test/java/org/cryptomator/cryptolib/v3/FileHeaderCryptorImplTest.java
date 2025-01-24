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
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

public class FileHeaderCryptorImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;
	private static final Map<Integer, byte[]> SEEDS = Collections.singletonMap(-1540072521, Base64.getDecoder().decode("fP4V4oAjsUw5DqackAvLzA0oP1kAQZ0f5YFZQviXSuU="));
	private static final byte[] KDF_SALT =  Base64.getDecoder().decode("HE4OP+2vyfLLURicF1XmdIIsWv0Zs6MobLKROUIEhQY=");
	private static final UVFMasterkey MASTERKEY = new UVFMasterkey(SEEDS, KDF_SALT, -1540072521, -1540072521);

	private FileHeaderCryptorImpl headerCryptor;

	@BeforeEach
	public void setup() {
		headerCryptor = new FileHeaderCryptorImpl(MASTERKEY, RANDOM_MOCK);

		// reset cipher state to avoid InvalidAlgorithmParameterExceptions due to IV-reuse
		GcmTestHelper.reset((mode, key, params) -> {
			try (ObjectPool.Lease<Cipher> cipher = CipherSupplier.AES_GCM.encryptionCipher(key, params)) {
				cipher.get();
			}
		});
	}

	@Test
	public void testHeaderSize() {
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.headerSize());
		Assertions.assertEquals(FileHeaderImpl.SIZE, headerCryptor.encryptHeader(headerCryptor.create()).limit());
	}

	@Test
	public void testSubkeyGeneration() {
		DestroyableSecretKey subkey = MASTERKEY.subKey(-1540072521, 32, "fileHeader".getBytes(), "AES");
		Assertions.assertArrayEquals(Base64.getDecoder().decode("PwnW2t/pK9dmzc+GTLdBSaB8ilcwsTq4sYOeiyo3cpU="), subkey.getEncoded());
	}

	@Test
	public void testEncryption() {
		DestroyableSecretKey contentKey = new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES");
		FileHeader header = new FileHeaderImpl(-1540072521, new byte[FileHeaderImpl.NONCE_LEN], contentKey);

		ByteBuffer ciphertext = headerCryptor.encryptHeader(header);

		Assertions.assertArrayEquals(Base64.getDecoder().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JTkKGj3hwERhnFmZek61Xtc="), ciphertext.array());
	}

	@Test
	public void testDecryption() throws AuthenticationFailedException {
		byte[] ciphertext = BaseEncoding.base64().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JTkKGj3hwERhnFmZek61Xtc=");
		FileHeaderImpl header = headerCryptor.decryptHeader(ByteBuffer.wrap(ciphertext));
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
	public void testDecryptionWithInvalidTag() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/TCwvp3StG0JTkKGj3hwERhnFmZek61XtX="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

	@Test
	public void testDecryptionWithInvalidCiphertext() {
		ByteBuffer ciphertext = ByteBuffer.wrap(BaseEncoding.base64().decode("dXZmAKQ0W7cAAAAAAAAAAAAAAAA/UGgFA8QGho7E1QTsHWyZIVFqabbGJ/XCwvp3StG0JTkKGj3hwERhnFmZek61Xtc="));

		Assertions.assertThrows(AuthenticationFailedException.class, () -> {
			headerCryptor.decryptHeader(ciphertext);
		});
	}

}
