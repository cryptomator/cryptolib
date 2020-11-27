package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.CryptoException;
import org.cryptomator.cryptolib.api.MasterkeyLoader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Optional;

public class MasterkeyFileTest {

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

	@Test
	public void testLoad() throws IOException, CryptoException {
		final String content = "{\"version\":3,\"scryptSalt\":\"AAAAAAAAAAA=\",\"scryptCostParam\":2,\"scryptBlockSize\":8," //
				+ "\"primaryMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"hmacMasterKey\":\"mM+qoQ+o0qvPTiDAZYt+flaC3WbpNAx1sTXaUzxwpy0M9Ctj6Tih/Q==\"," //
				+ "\"versionMac\":\"iUmRRHITuyJsJbVNqGNw+82YQ4A3Rma7j/y1v0DCVLA=\"}";

		MasterkeyFile masterkeyFile = MasterkeyFile.withContent(new ByteArrayInputStream(content.getBytes()));
		MasterkeyLoader keyLoader = masterkeyFile.unlock("asd", new byte[0], Optional.empty());
		Assertions.assertNotNull(keyLoader);
	}

}