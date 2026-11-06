package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.common.DestroyableSecretKey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class FileHeaderImplTest {

	private static final int SEED_ID = 1925996179;

	@Test
	public void testConstructionFailsWithInvalidNonceSize() {
		DestroyableSecretKey contentKey = new DestroyableSecretKey(new byte[FileHeaderImpl.CONTENT_KEY_LEN], "AES");
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new FileHeaderImpl(SEED_ID, new byte[3], contentKey);
		});
	}

	@Test
	public void testDestruction() {
		byte[] nonNullKey = new byte[FileHeaderImpl.CONTENT_KEY_LEN];
		Arrays.fill(nonNullKey, (byte) 0x42);
		DestroyableSecretKey contentKey = new DestroyableSecretKey(nonNullKey, "AES");
		FileHeaderImpl header = new FileHeaderImpl(SEED_ID, new byte[FileHeaderImpl.NONCE_LEN], contentKey);
		Assertions.assertFalse(header.isDestroyed());
		header.destroy();
		Assertions.assertTrue(header.isDestroyed());
		Assertions.assertTrue(contentKey.isDestroyed());
	}

}
