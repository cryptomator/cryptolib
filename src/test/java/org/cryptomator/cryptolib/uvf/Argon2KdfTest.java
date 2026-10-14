package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.Argon2Params;
import org.cryptomator.cryptolib.api.VaultConfigLoadException;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Argon2KdfTest {

	private static final byte[] SALT = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	private static final SecureRandom FIXED_SALT = new SecureRandomMock(bytes -> System.arraycopy(SALT, 0, bytes, 0, Math.min(SALT.length, bytes.length)));

	private static Map<String, Object> validHeader() {
		Map<String, Object> header = new HashMap<>();
		header.put("alg", "A256KW");
		header.put("kid", "org.cryptomator.password.argon2");
		header.put("org.cryptomator.password.argon2.salt", "AAECAwQFBgcICQoLDA0ODw");
		header.put("org.cryptomator.password.argon2.memoryKiB", 64L);
		header.put("org.cryptomator.password.argon2.iterations", 1L);
		header.put("org.cryptomator.password.argon2.parallelism", 1L);
		return header;
	}

	@Test
	@DisplayName("new header params carry a 16 byte salt and the cost parameters")
	public void testNewHeaderParams() {
		Map<String, Object> params = Argon2Kdf.newHeaderParams(new Argon2Params(1024, 2, 3), FIXED_SALT);
		Assertions.assertEquals("AAECAwQFBgcICQoLDA0ODw", params.get("org.cryptomator.password.argon2.salt"));
		Assertions.assertEquals(1024, params.get("org.cryptomator.password.argon2.memoryKiB"));
		Assertions.assertEquals(2, params.get("org.cryptomator.password.argon2.iterations"));
		Assertions.assertEquals(3, params.get("org.cryptomator.password.argon2.parallelism"));
		Assertions.assertEquals(4, params.size());
		Assertions.assertEquals(params, Argon2Kdf.headerParams(params));
	}

	@Test
	@DisplayName("pinned vector: Argon2id v1.3, password \"password\", salt 00..0f, m=64 KiB, t=1, p=1")
	public void testPinnedVector() {
		byte[] key = Argon2Kdf.deriveKey("password", validHeader());
		Assertions.assertEquals(32, key.length);
		Assertions.assertEquals("nEkwIodzSOA0cZvOEQyZMB5dTRasrMaoKQAP8gRLGww", Base64.getUrlEncoder().withoutPadding().encodeToString(key));
		Assertions.assertArrayEquals(key, Argon2Kdf.deriveKey("password", validHeader()), "deterministic");
		Assertions.assertFalse(java.util.Arrays.equals(key, Argon2Kdf.deriveKey("Password", validHeader())));
	}

	@ParameterizedTest(name = "{0}")
	@ValueSource(strings = {"org.cryptomator.password.argon2.salt", "org.cryptomator.password.argon2.memoryKiB", "org.cryptomator.password.argon2.iterations", "org.cryptomator.password.argon2.parallelism"})
	@DisplayName("missing header parameters are rejected")
	public void testMissingParam(String param) {
		Map<String, Object> header = validHeader();
		header.remove(param);
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", header));
	}

	@Test
	@DisplayName("invalid header parameters are rejected")
	public void testInvalidParams() {
		Map<String, Object> header = validHeader();
		header.put("org.cryptomator.password.argon2.salt", "AAECAwQ"); // 5 bytes
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", header));
		header.put("org.cryptomator.password.argon2.salt", "not base64url!");
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", header));
		header.put("org.cryptomator.password.argon2.salt", 42L);
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", header));
		Map<String, Object> hugeMemory = validHeader();
		hugeMemory.put("org.cryptomator.password.argon2.memoryKiB", (long) Argon2Params.MAX_MEMORY_KIB + 1);
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", hugeMemory));
		Map<String, Object> overflow = validHeader();
		overflow.put("org.cryptomator.password.argon2.iterations", 1L << 32 | 1L);
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", overflow));
		Map<String, Object> nonNumeric = validHeader();
		nonNumeric.put("org.cryptomator.password.argon2.parallelism", "1");
		Assertions.assertThrows(VaultConfigLoadException.class, () -> Argon2Kdf.deriveKey("password", nonNumeric));
	}

}
