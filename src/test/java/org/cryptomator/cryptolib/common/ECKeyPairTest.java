package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class ECKeyPairTest {

	@Test
	public void testConstructorFailsForInvalidAlgorithm() throws NoSuchAlgorithmException {
		KeyPair rsaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new ECKeyPair(rsaKeyPair);
		});
	}

	@Nested
	@DisplayName("With undestroyed key...")
	public class WithUndestroyed {

		private KeyPair keyPair1;
		private KeyPair keyPair2;
		private ECKeyPair ecKeyPair;

		@BeforeEach
		public void setup() throws NoSuchAlgorithmException {
			this.keyPair1 = KeyPairGenerator.getInstance("EC").generateKeyPair();
			this.keyPair2 = KeyPairGenerator.getInstance("EC").generateKeyPair();
			this.ecKeyPair = new ECKeyPair(keyPair1);
		}

		@Test
		public void testGetPublicKey() {
			Assertions.assertSame(keyPair1.getPublic(), ecKeyPair.getPublic());
		}

		@Test
		public void testGetPrivate() {
			Assertions.assertSame(keyPair1.getPrivate(), ecKeyPair.getPrivate());
		}

		@Test
		public void testIsDestroyed() {
			Assertions.assertFalse(ecKeyPair.isDestroyed());
		}

		@Test
		public void testDestroy() {
			Assertions.assertDoesNotThrow(ecKeyPair::destroy);
		}

		@Test
		public void testEquals() {
			ECKeyPair other1 = new ECKeyPair(keyPair1);
			ECKeyPair other2 = new ECKeyPair(keyPair2);
			Assertions.assertNotSame(ecKeyPair, other1);
			Assertions.assertEquals(ecKeyPair, other1);
			Assertions.assertNotSame(ecKeyPair, other2);
			Assertions.assertNotEquals(ecKeyPair, other2);
		}

		@Test
		public void testHashCode() {
			ECKeyPair other1 = new ECKeyPair(keyPair1);
			ECKeyPair other2 = new ECKeyPair(keyPair2);
			Assertions.assertEquals(ecKeyPair.hashCode(), other1.hashCode());
			Assertions.assertNotEquals(ecKeyPair.hashCode(), other2.hashCode());
		}

	}

	@Nested
	@DisplayName("With destroyed key...")
	public class WithDestroyed {

		private KeyPair keyPair;
		private ECKeyPair ecKeyPair;

		@BeforeEach
		public void setup() throws NoSuchAlgorithmException {
			this.keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
			this.ecKeyPair = new ECKeyPair(keyPair);
			this.ecKeyPair.destroy();
		}

		@Test
		public void testGetPublicKey() {
			Assertions.assertThrows(IllegalStateException.class, ecKeyPair::getPublic);
		}

		@Test
		public void testGetPrivate() {
			Assertions.assertThrows(IllegalStateException.class, ecKeyPair::getPrivate);
		}

		@Test
		public void testIsDestroyed() {
			Assertions.assertTrue(ecKeyPair.isDestroyed());
		}

		@Test
		public void testDestroy() {
			Assertions.assertDoesNotThrow(ecKeyPair::destroy);
		}

	}


}