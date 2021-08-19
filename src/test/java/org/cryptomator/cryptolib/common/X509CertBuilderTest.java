package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;

public class X509CertBuilderTest {

	@Test
	@DisplayName("init() with RSA key and EC signature")
	public void testInitWithInvalidKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		String signingAlg = "SHA256withECDSA";

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			X509CertBuilder.init(keyPair, signingAlg);
		});
	}

	@Test
	@DisplayName("init() with RSA key and RSA signature")
	public void testInitWithRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		String signingAlg = "SHA256withRSA";
		
		Assertions.assertDoesNotThrow(() -> {
			X509CertBuilder.init(keyPair, signingAlg);
		});
	}

	@Test
	@DisplayName("init() with EC key and EC signature")
	public void testInitWithECKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
		String signingAlg = "SHA256withECDSA";

		Assertions.assertDoesNotThrow(() -> {
			X509CertBuilder.init(keyPair, signingAlg);
		});
	}

	@Nested
	@DisplayName("With initialized builder...")
	public class WithInitialized {

		private KeyPair keyPair;
		private X509CertBuilder builder;

		@BeforeEach
		public void setup() throws NoSuchAlgorithmException {
			this.keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
			this.builder = X509CertBuilder.init(keyPair, "SHA256withECDSA");
		}

		@Test
		@DisplayName("set invalid issuer")
		public void testWithInvalidIssuer() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				builder.withIssuer("Test");
			});
		}

		@Test
		@DisplayName("set invalid subject")
		public void testWithInvalidSubject() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				builder.withSubject("Test");
			});
		}

		@Test
		@DisplayName("build() with missing issuer")
		public void testBuildWithMissingIssuer() {
			builder.withSubject("CN=Test") //
					.withNotBefore(Instant.now()) //
					.withNotAfter(Instant.now().minusSeconds(3600));
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
		@DisplayName("build() with missing subject")
		public void testBuildWithMissingSubject() {
			builder.withIssuer("CN=Test") //
					.withNotBefore(Instant.now()) //
					.withNotAfter(Instant.now().minusSeconds(3600));
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
		@DisplayName("build() with missing notBefore")
		public void testBuildWithMissingNotBefore() {
			builder.withIssuer("CN=Test") //
					.withSubject("CN=Test") //
					.withNotAfter(Instant.now().minusSeconds(3600));
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
		@DisplayName("build() with missing notAfter")
		public void testBuildWithMissingNotAfter() {
			builder.withIssuer("CN=Test") //
					.withSubject("CN=Test") //
					.withNotBefore(Instant.now());
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
		@DisplayName("build() with invalid notAfter")
		public void testBuildWithInvalidNotAfter() {
			builder.withIssuer("CN=Test") //
					.withSubject("CN=Test") //
					.withNotBefore(Instant.now()) //
					.withNotAfter(Instant.now().minusSeconds(1));
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
		@DisplayName("build() with all params set")
		public void testBuild() throws CertificateException {
			X509Certificate cert = builder //
					.withIssuer("CN=Test") //
					.withSubject("CN=Test") //
					.withNotBefore(Instant.now()) //
					.withNotAfter(Instant.now().plusSeconds(3600)) //
					.build();

			Assertions.assertNotNull(cert);
			Assertions.assertDoesNotThrow(() -> {
				cert.verify(keyPair.getPublic());
			});
			Assertions.assertDoesNotThrow(() -> {
				cert.checkValidity();
			});
		}

	}

}