package org.cryptomator.cryptolib.uvf;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Base64;
import java.util.UUID;
import java.util.stream.Stream;

public class UvfNamesTest {

	private static final byte[] ROOT_DIR_ID = Base64.getDecoder().decode("24UBEDeGu5taq7U4GqyA0MXUXb9HTYS6p3t9vvHGJAc=");

	private UvfSeeds seeds;
	private UvfNames names;

	@BeforeEach
	public void setup() {
		seeds = UvfSeedsTest.testSeeds();
		names = new UvfNames(seeds);
	}

	@AfterEach
	public void tearDown() {
		names.destroy();
		seeds.destroy();
	}

	private static Stream<String> filenameGenerator() {
		return Stream.generate(UUID::randomUUID).map(UUID::toString).limit(50);
	}

	@Test
	@DisplayName("hash root dir id vector")
	public void testHashRootDirId() {
		Assertions.assertEquals("6DYU3E5BTPAZ4DWEQPQK3AIHX2DXSPHG", names.hashDirectoryId(ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@ParameterizedTest(name = "decrypt(encrypt({0}))")
	@MethodSource("filenameGenerator")
	public void testRoundTrip(String name) throws AuthenticationFailedException {
		String encrypted1 = names.encryptName(name, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		String encrypted2 = names.encryptName(name, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertEquals(encrypted1, encrypted2);
		Assertions.assertFalse(encrypted1.contains("="), "unpadded base64url");
		Assertions.assertEquals(name, names.decryptName(encrypted1, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("names are bound to the directory id")
	public void testWrongDirId() {
		String encrypted = names.encryptName("test", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(encrypted, new byte[32], UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("names are normalized to NFC")
	public void testNfc() throws AuthenticationFailedException {
		String nfd = "über.txt"; // u + combining diaeresis
		String nfc = "über.txt";
		Assertions.assertEquals(names.encryptName(nfc, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID), names.encryptName(nfd, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		Assertions.assertEquals(nfc, names.decryptName(names.encryptName(nfd, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID), ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("malformed and tampered ciphertext")
	public void testInvalidCiphertext() {
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName("lol", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
		String encrypted = names.encryptName("test", ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID);
		String tampered = (encrypted.charAt(0) == 'A' ? 'B' : 'A') + encrypted.substring(1);
		Assertions.assertThrows(AuthenticationFailedException.class, () -> names.decryptName(tampered, ROOT_DIR_ID, UvfSeedsTest.TEST_SEED_ID));
	}

	@Test
	@DisplayName("unknown seed")
	public void testUnknownSeed() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> names.encryptName("test", ROOT_DIR_ID, 42));
	}

}
