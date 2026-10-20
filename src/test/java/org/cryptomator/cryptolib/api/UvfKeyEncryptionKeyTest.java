package org.cryptomator.cryptolib.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;

class UvfKeyEncryptionKeyTest {

	@Test
	@DisplayName("password recipient")
	void testPassword() {
		UvfKeyEncryptionKey key = UvfKeyEncryptionKey.password("secret");
		Assertions.assertEquals(UvfLockedVault.PASSWORD_KID, key.kid());
		Assertions.assertEquals("secret", key.password());
		Assertions.assertEquals(Argon2Params.DEFAULT, key.argon2Params());
		Assertions.assertNull(key.memberKey());
		Argon2Params cheap = new Argon2Params(64, 1, 1);
		Assertions.assertSame(cheap, UvfKeyEncryptionKey.password("secret", cheap).argon2Params());
	}

	@Test
	@DisplayName("member key recipient must be a 256 bit key")
	void testMemberKey() {
		SecretKeySpec aes = new SecretKeySpec(new byte[32], "AES");
		UvfKeyEncryptionKey key = UvfKeyEncryptionKey.memberKey(aes);
		Assertions.assertEquals(UvfLockedVault.MEMBER_KEY_KID, key.kid());
		Assertions.assertSame(aes, key.memberKey());
		Assertions.assertNull(key.password());
		Assertions.assertNull(key.argon2Params());
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfKeyEncryptionKey.memberKey(new SecretKeySpec(new byte[16], "AES")));
	}

}
