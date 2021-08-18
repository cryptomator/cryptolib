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
	public void testInitWithInvalidKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		String signingAlg = "SHA256withECDSA";

		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			X509CertBuilder.init(keyPair, signingAlg);
		});
	}

	@Test
	public void testInitWithRSAKeyPair() throws NoSuchAlgorithmException {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		String signingAlg = "SHA256withRSA";
		
		Assertions.assertDoesNotThrow(() -> {
			X509CertBuilder.init(keyPair, signingAlg);
		});
	}

	@Test
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
		public void testWithInvalidIssuer() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				builder.withIssuer("Test");
			});
		}

		@Test
		public void testWithInvalidSubject() {
			Assertions.assertThrows(IllegalArgumentException.class, () -> {
				builder.withSubject("Test");
			});
		}

		@Test
		public void testBuildWithMissingParams() {
			Assertions.assertThrows(IllegalStateException.class, () -> {
				builder.build();
			});
		}

		@Test
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