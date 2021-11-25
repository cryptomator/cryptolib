package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.ECGenParameterSpec;

public class Pkcs12HelperTest {

	private Path p12File;

	@BeforeEach
	public void setup(@TempDir Path tmpDir) throws NoSuchAlgorithmException {
		this.p12File = tmpDir.resolve("test.p12");
	}

	@Test
	@DisplayName("attempt export RSA key pair with EC signature alg")
	public void testExportWithInappropriateSignatureAlg() throws NoSuchAlgorithmException, IOException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		try (OutputStream out = Files.newOutputStream(p12File, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			char[] passphrase = "topsecret".toCharArray();
			Assertions.assertThrows(Pkcs12Exception.class, () -> {
				Pkcs12Helper.exportTo(keyPair, out, passphrase, "SHA256withECDSA");
			});
		}
	}

	@Test
	@DisplayName("attempt export EC key pair with EC signature alg")
	public void testExport() throws NoSuchAlgorithmException, IOException {
		KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
		try (OutputStream out = Files.newOutputStream(p12File, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
			char[] passphrase = "topsecret".toCharArray();
			Assertions.assertDoesNotThrow(() -> {
				Pkcs12Helper.exportTo(keyPair, out, passphrase, "SHA256withECDSA");
			});
		}
	}

	@Nested
	@DisplayName("With exported PKCS12 file...")
	public class WithExported {

		private KeyPair keyPair;
		private char[] passphrase = "topsecret".toCharArray();

		@BeforeEach
		public void setup() throws NoSuchAlgorithmException, IOException, InvalidAlgorithmParameterException {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("EC");
			keyPairGen.initialize(new ECGenParameterSpec("secp384r1"));
			this.keyPair = keyPairGen.generateKeyPair();
			try (OutputStream out = Files.newOutputStream(p12File, StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW)) {
				Pkcs12Helper.exportTo(keyPair, out, passphrase, "SHA384withECDSA");
			}
		}

		@Test
		@DisplayName("attempt import with invalid passphrase")
		public void testImportWithInvalidPassphrase() throws IOException {
			try (InputStream in = Files.newInputStream(p12File, StandardOpenOption.READ)) {
				char[] wrongPassphrase = "bottompublic".toCharArray();
				Assertions.assertThrows(Pkcs12PasswordException.class, () -> {
					Pkcs12Helper.importFrom(in, wrongPassphrase);
				});
			}
		}

		@Test
		@DisplayName("attempt import with valid passphrase")
		public void testImportWithValidPassphrase() throws IOException {
			try (InputStream in = Files.newInputStream(p12File, StandardOpenOption.READ)) {
				KeyPair imported = Pkcs12Helper.importFrom(in, passphrase);
				Assertions.assertEquals(keyPair.getPublic().getAlgorithm(), imported.getPublic().getAlgorithm());
				Assertions.assertArrayEquals(keyPair.getPublic().getEncoded(), imported.getPublic().getEncoded());
			}
		}

	}

}