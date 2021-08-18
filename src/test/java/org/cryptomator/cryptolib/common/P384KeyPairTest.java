package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;

public class P384KeyPairTest {

	@Test
	public void testGenerate() {
		P384KeyPair keyPair1 = P384KeyPair.generate();
		P384KeyPair keyPair2 = P384KeyPair.generate();
		Assertions.assertNotNull(keyPair1);
		Assertions.assertNotNull(keyPair2);
		Assertions.assertNotEquals(keyPair1, keyPair2);
	}

	@Test
	public void testStore(@TempDir Path tmpDir) {
		Path p12File = tmpDir.resolve("test.p12");
		P384KeyPair keyPair = P384KeyPair.generate();

		Assertions.assertDoesNotThrow(() -> {
			keyPair.store(p12File, "topsecret".toCharArray());
		});
	}

	@Nested
	@DisplayName("With stored PKCS12 file...")
	public class WithStored {

		private P384KeyPair origKeyPair;
		private Path p12File;

		@BeforeEach
		public void setup(@TempDir Path tmpDir) throws IOException {
			this.origKeyPair = P384KeyPair.generate();
			this.p12File = tmpDir.resolve("test.p12");
			origKeyPair.store(p12File, "topsecret".toCharArray());
		}

		@Test
		public void testLoadWithInvalidPassphrase() {
			char[] wrongPassphrase = "bottompublic".toCharArray();
			Assertions.assertThrows(Pkcs12PasswordException.class, () -> {
				P384KeyPair.load(p12File, wrongPassphrase);
			});
		}

		@Test
		public void testLoadWithValidPassphrase() throws IOException {
			P384KeyPair keyPair = P384KeyPair.load(p12File, "topsecret".toCharArray());
			Assertions.assertEquals(origKeyPair, keyPair);
		}

	}

}