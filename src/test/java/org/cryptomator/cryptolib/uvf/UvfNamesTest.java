package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Base64;
import java.util.UUID;
import java.util.stream.Stream;

class UvfNamesTest {

	private static final byte[] ROOT_DIR_ID = Base64.getDecoder().decode("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=");

	private UvfSeeds seeds;
	private UvfNames names;

	@BeforeEach
	void setup() {
		seeds = UvfSeedsTest.testSeeds();
		names = new UvfNames(seeds);
	}

	@AfterEach
	void tearDown() {
		names.destroy();
		seeds.destroy();
	}

	private static Stream<String> filenameGenerator() {
		return Stream.generate(UUID::randomUUID).map(UUID::toString).limit(50);
	}

	@Test
	@DisplayName("hash root dir id vector")
	void testHashRootDirId() {
		Assertions.assertEquals("6DYU3E5BTPAZ4DWEQPQK3AIHX2DXSPHG", names.hashDirectoryId(ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	void testRoundTrip(String name) throws AuthenticationFailedException {
		String encrypted1 = names.encryptName(name, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		String encrypted2 = names.encryptName(name, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertFalse(encrypted1.contains("="), "unpadded base64url");
		Assertions.assertEquals(name, names.decryptName(encrypted1, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("names are bound to the directory id")
	void testWrongDirId() {
		String encrypted = names.encryptName("test", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(encrypted, new byte[32], UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("names are normalized to NFC")
	void testNfc() throws AuthenticationFailedException {
		String nfd = "über.txt"; // u + combining diaeresis
		String nfc = "über.txt";
		Assertions.assertEquals(names.encryptName(nfc, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID), names.encryptName(nfd, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		Assertions.assertEquals(nfc, names.decryptName(names.encryptName(nfd, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID), ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("malformed and tampered ciphertext")
	void testInvalidCiphertext() {
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName("lol", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		String encrypted = names.encryptName("test", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		String tampered = (encrypted.charAt(0) == 'A' ? 'B' : 'A') + encrypted.substring(1);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(tampered, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("non-canonical base64url is rejected")
	void testNonCanonicalCiphertext() throws AuthenticationFailedException {
		String encrypted = names.encryptName("test", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertEquals("test", names.decryptName(encrypted, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		// the last character of a 20-byte ciphertext encodes 4 payload bits followed by 2 trailing bits; a different last character with the same payload bits decodes to the same bytes
		char last = encrypted.charAt(encrypted.length() - 1);
		String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		char nonCanonical = alphabet.charAt(alphabet.indexOf(last) ^ 0x01);
		String tampered = encrypted.substring(0, encrypted.length() - 1) + nonCanonical;
		Assertions.assertArrayEquals(Base64.getUrlDecoder().decode(encrypted), Base64.getUrlDecoder().decode(tampered), "same bytes, different encoding");
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(tampered, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(encrypted + "=", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID), "padding");
	}

	@ParameterizedTest(name = "decrypted name {0} is rejected")
	@ValueSource(strings = {"", ".", "..", "a/b", "/", "a\u0000b"})
	void testInvalidCleartextNames(String name) {
		String encrypted = names.encryptName(name, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(encrypted, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("unknown seed")
	void testUnknownSeed() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> names.encryptName("test", ROOT_DIR_ID, 42));
	}

}
