package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.InvalidPassphraseException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.cryptomator.cryptolib.api.UnsupportedVaultFormatException;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Optional;

import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;

public class MasterkeyFileTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Test
	public void testParse() throws IOException {
		final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

		MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
		Assertions.assertNotNull(masterkeyFile);
	}

	@Test
	public void testParseInvalid() {
		final String content = "{\"foo\": 42}";

		Assertions.assertThrows(IOException.class, () -> {
			MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
		});
	}

	@Test
	public void testParseMalformed() {
		final String content = "not even json";

		Assertions.assertThrows(IOException.class, () -> {
			MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
		});
	}

	@Nested
	class Unlock {

		@Test
		public void testUnlockWithCorrectPassword() throws IOException, CryptoException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			MasterkeyLoader keyLoader = masterkeyFile.unlock("asd", new byte[0], Optional.of(3));
			Assertions.assertNotNull(keyLoader);
		}

		@Test
		public void testUnlockWithIncorrectPassword() throws IOException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			Assertions.assertThrows(InvalidPassphraseException.class, () -> {
				masterkeyFile.unlock("qwe", new byte[0], Optional.empty());
			});
		}

		@Test
		public void testUnlockWithIncorrectPepper() throws IOException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			Assertions.assertThrows(InvalidPassphraseException.class, () -> {
				masterkeyFile.unlock("qwe", new byte[3], Optional.empty());
			});
		}

		@Test
		public void testUnlockWithIncorrectVaultFormat() throws IOException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> {
				masterkeyFile.unlock("asd", new byte[0], Optional.of(42));
			});
		}

		@Test
		public void testUnlockWithIncorrectVersionMac() throws IOException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"AAAA\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			Assertions.assertThrows(UnsupportedVaultFormatException.class, () -> {
				masterkeyFile.unlock("asd", new byte[0], Optional.of(3));
			});
		}

		@Test
		public void testUnlockWithIgnoredVersionMac() throws IOException, CryptoException {
			final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
					+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
					+ "\"versionMac\":\"AAAA\"}";

			MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
			MasterkeyLoader keyLoader = masterkeyFile.unlock("asd", new byte[0], Optional.empty());
			Assertions.assertNotNull(keyLoader);
		}

	}

	@Nested
	class Lock {

		@Test
		public void testLock() {
			byte[] serialized;
			try (Masterkey masterkey = Masterkey.createFromRaw(new byte[64])) {
				serialized = MasterkeyFile.lock(masterkey, "asd", new byte[0], 3, RANDOM_MOCK);
			}

			String serializedStr = new String(serialized, StandardCharsets.UTF_8);
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"version\": 3"));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptSalt\": \"AAAAAAAAAAA=\""));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptCostParam\": 32768"));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"scryptBlockSize\": 8"));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"primaryMasterKey\": \"bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==\""));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"hmacMasterKey\": \"bOuDTfSpTHJrM4G321gts1QL+TFAZ3I6S/QHwim39pz+t+/K9IYy6g==\""));
			MatcherAssert.assertThat(serializedStr, CoreMatchers.containsString("\"versionMac\": \"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\""));
		}

		@Test
		public void testLockWithDifferentPeppers() {
			byte[] serialized1, serialized2;
			try (Masterkey masterkey = Masterkey.createFromRaw(new byte[64])) {
				serialized1 = MasterkeyFile.lock(masterkey, "asd", new byte[] {(byte) 0x01}, 8, RANDOM_MOCK);
				serialized2 = MasterkeyFile.lock(masterkey, "asd", new byte[] {(byte) 0x02}, 8, RANDOM_MOCK);
			}

			MatcherAssert.assertThat(serialized1, not(equalTo(serialized2)));
		}

	}

	@Test
	public void testChangePassword() throws IOException, CryptoException {
		Masterkey masterkey = Masterkey.createFromRaw(new byte[64]);
		byte[] serialized1 = MasterkeyFile.lock(masterkey, "password", new byte[0], 42, RANDOM_MOCK);
		byte[] serialized2 = MasterkeyFile.changePassphrase(serialized1, "password", "betterPassw0rd!", new byte[0], RANDOM_MOCK);
		Masterkey unlocked1 = MasterkeyFile.withContent(new ByteArrayInputStream(serialized1)).unlock("password", new byte[0], Optional.of(42)).loadKey(MasterkeyFileLoader.KEY_ID);
		Masterkey unlocked2 = MasterkeyFile.withContent(new ByteArrayInputStream(serialized2)).unlock("betterPassw0rd!", new byte[0], Optional.of(42)).loadKey(MasterkeyFileLoader.KEY_ID);

		MatcherAssert.assertThat(serialized1, not(equalTo(serialized2)));
		Assertions.assertNotSame(unlocked1, unlocked2);
		Assertions.assertArrayEquals(unlocked1.getEncoded(), unlocked2.getEncoded());
	}
}