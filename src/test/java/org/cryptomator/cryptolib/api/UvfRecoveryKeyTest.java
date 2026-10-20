package org.cryptomator.cryptolib.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

class UvfRecoveryKeyTest {

	@Test
	@DisplayName("generate() yields a P-384 key pair")
	void testGenerate() {
		UvfRecoveryKey key = UvfRecoveryKey.generate(new SecureRandom());
		Assertions.assertEquals(384, key.publicKey().getParams().getOrder().bitLength());
		Assertions.assertNotNull(key.privateKey());
	}

	@Test
	@DisplayName("of(KeyPair) requires P-384")
	void testOfKeyPair() throws Exception {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
		generator.initialize(new ECGenParameterSpec("secp384r1"));
		KeyPair p384 = generator.generateKeyPair();
		UvfRecoveryKey key = UvfRecoveryKey.of(p384);
		Assertions.assertSame(p384.getPublic(), key.publicKey());
		Assertions.assertSame(p384.getPrivate(), key.privateKey());
		generator.initialize(new ECGenParameterSpec("secp256r1"));
		KeyPair p256 = generator.generateKeyPair();
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfRecoveryKey.of(p256));
		KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
		rsa.initialize(1024);
		Assertions.assertThrows(IllegalArgumentException.class, () -> UvfRecoveryKey.of(rsa.generateKeyPair()));
	}

	@Test
	@DisplayName("of(ECPublicKey) has no private part")
	void testOfPublicKey() {
		ECPublicKey publicKey = UvfRecoveryKey.generate(new SecureRandom()).publicKey();
		UvfRecoveryKey key = UvfRecoveryKey.of(publicKey);
		Assertions.assertSame(publicKey, key.publicKey());
		Assertions.assertNull(key.privateKey());
	}

}
