package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Path;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class P384KeyPairTest {

	@Test
	@DisplayName("generate()")
	public void testGenerate() {
		P384KeyPair keyPair1 = P384KeyPair.generate();
		P384KeyPair keyPair2 = P384KeyPair.generate();
		Assertions.assertNotNull(keyPair1);
		Assertions.assertNotNull(keyPair2);
		Assertions.assertNotEquals(keyPair1, keyPair2);
	}

	@Test
	@DisplayName("create()")
	public void testCreate() throws InvalidKeySpecException {
		X509EncodedKeySpec publicKey = new X509EncodedKeySpec(Base64.getDecoder().decode("MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERxQR+NRN6Wga01370uBBzr2NHDbKIC56tPUEq2HX64RhITGhii8Zzbkb1HnRmdF0aq6uqmUy4jUhuxnKxsv59A6JeK7Unn+mpmm3pQAygjoGc9wrvoH4HWJSQYUlsXDu"));
		PKCS8EncodedKeySpec privateKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode("ME8CAQAwEAYHKoZIzj0CAQYFK4EEACIEODA2AgEBBDEA6QybmBitf94veD5aCLr7nlkF5EZpaXHCfq1AXm57AKQyGOjTDAF9EQB28fMywTDQ"));

		P384KeyPair keyPair = P384KeyPair.create(publicKey, privateKey);
		Assertions.assertNotNull(keyPair);
	}

	@Test
	@DisplayName("store(...)")
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
		@DisplayName("load(...) with invalid passphrase")
		public void testLoadWithInvalidPassphrase() {
			char[] wrongPassphrase = "bottompublic".toCharArray();
			Assertions.assertThrows(Pkcs12PasswordException.class, () -> {
				P384KeyPair.load(p12File, wrongPassphrase);
			});
		}

		@Test
		@DisplayName("load(...) with valid passphrase")
		public void testLoadWithValidPassphrase() throws IOException {
			P384KeyPair keyPair = P384KeyPair.load(p12File, "topsecret".toCharArray());
			Assertions.assertEquals(origKeyPair, keyPair);
		}

	}

}