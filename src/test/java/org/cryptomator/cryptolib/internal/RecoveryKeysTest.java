package org.cryptomator.cryptolib.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.Base64;
import java.util.Random;

/**
 * Vectors from Cryptomator Hub's {@code vaultFormat8.spec.ts} / {@code universalVaultFormat.spec.ts} and Cryptomator's {@code RecoveryKeyFactoryTest}.
 */
public class RecoveryKeysTest {

	@Nested
	@DisplayName("CVF8 (unpadded)")
	public class Unpadded {

		private static final String TEST_KEY_WORDS = "water water water water water water water water water water water water water water water water water " //
				+ "water water water water asset partly partly partly partly partly partly partly partly partly partly " //
				+ "partly partly partly partly partly partly partly partly partly partly option twist";
		private static final String ACTUAL_KEY_WORDS = "pathway lift abuse plenty export texture gentleman landscape beyond ceiling around leaf cafe charity " //
				+ "border breakdown victory surely computer cat linger restrict infer crowd live computer true written amazed " //
				+ "investor boot depth left theory snow whereby terminal weekly reject happiness circuit partial cup ad";

		@Test
		@DisplayName("Hub test key 0x55*32 || 0x77*32")
		public void testHubTestKey() {
			byte[] key = new byte[64];
			Arrays.fill(key, 0, 32, (byte) 0x55);
			Arrays.fill(key, 32, 64, (byte) 0x77);
			Assertions.assertEquals(TEST_KEY_WORDS, RecoveryKeys.encode(key, false));
			Assertions.assertArrayEquals(key, RecoveryKeys.decode(TEST_KEY_WORDS, false));
		}

		@Test
		@DisplayName("Hub actual key")
		public void testHubActualKey() {
			byte[] key = Base64.getUrlDecoder().decode("uwHiVreDbmv47K7oZzlwZbHcEql2Z29brbgFxKA7i54pXVPoHoxKK5rzZS3VEhPxHegQKCwa5Mk4ep7OsYutAw");
			Assertions.assertArrayEquals(key, RecoveryKeys.decode("\n  " + ACTUAL_KEY_WORDS.replace("charity ", "charity\n  ") + "\n", false), "whitespace-tolerant");
			Assertions.assertEquals(ACTUAL_KEY_WORDS, RecoveryKeys.encode(key, false));
		}

		@Test
		@DisplayName("invalid keys")
		public void testInvalid() {
			assertThrowsWithMessage("multiple of two words", () -> RecoveryKeys.decode("pathway", false));
			assertThrowsWithMessage("not in dictionary", () -> RecoveryKeys.decode("hallo bonjour", false));
			assertThrowsWithMessage("Invalid recovery key length", () -> RecoveryKeys.decode("", false));
			assertThrowsWithMessage("Invalid recovery key checksum", () -> RecoveryKeys.decode(ACTUAL_KEY_WORDS.replace("cup ad", "cup wrong"), false));
			Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeys.decode("pathway lift", false));
			Assertions.assertThrows(IllegalArgumentException.class, () -> RecoveryKeys.encode(new byte[2], false), "length not encodable without padding");
		}

	}

	@Nested
	@DisplayName("UVF (padded)")
	public class Padded {

		@ParameterizedTest(name = "{0} bytes")
		@ValueSource(ints = {0, 1, 2, 3, 4, 64, 80, 185, 194})
		@DisplayName("round trip with 1-3 padding bytes")
		public void testRoundTrip(int len) {
			byte[] key = new byte[len];
			new Random(len).nextBytes(key);
			String words = RecoveryKeys.encode(key, true);
			int expectedWords = (len + 2 + 3 - (len + 2) % 3) / 3 * 2;
			Assertions.assertEquals(expectedWords, words.split(" ").length);
			Assertions.assertArrayEquals(key, RecoveryKeys.decode(words, true));
		}

		@Test
		@DisplayName("invalid keys (Hub's cases)")
		public void testInvalid() {
			assertThrowsWithMessage("not in dictionary", () -> RecoveryKeys.decode("hallo bonjour", true));
			assertThrowsWithMessage("Invalid padding", () -> RecoveryKeys.decode("cult hold all away buck do law relaxed other stimulus", true));
			assertThrowsWithMessage("Invalid padding", () -> RecoveryKeys.decode("", true));
			assertThrowsWithMessage("Invalid recovery key checksum", () -> RecoveryKeys.decode("ah ah", true), "00 10 01: padding ok, checksum of empty key wrong");
		}

	}

	private static void assertThrowsWithMessage(String message, org.junit.jupiter.api.function.Executable executable) {
		assertThrowsWithMessage(message, executable, null);
	}

	private static void assertThrowsWithMessage(String message, org.junit.jupiter.api.function.Executable executable, String reason) {
		IllegalArgumentException e = Assertions.assertThrows(IllegalArgumentException.class, executable, reason);
		Assertions.assertTrue(e.getMessage().contains(message), "expected message containing '" + message + "' but was: " + e.getMessage());
	}

}
