package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class ECKeyPairTest {

	@Test
	public void testConstructorFailsForInvalidAlgorithm() throws NoSuchAlgorithmException {
		KeyPair rsaKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		ECParameterSpec curveParams = Mockito.mock(ECParameterSpec.class);
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new ECKeyPair(rsaKeyPair, curveParams);
		});
	}

	private ECParameterSpec getParamsFromPublicKey(KeyPair keyPair) {
		return ((ECPublicKey)keyPair.getPublic()).getParams();
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
			this.ecKeyPair = new ECKeyPair(keyPair1, getParamsFromPublicKey(keyPair1));
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
			ECKeyPair other1 = new ECKeyPair(keyPair1, getParamsFromPublicKey(keyPair1));
			ECKeyPair other2 = new ECKeyPair(keyPair2, getParamsFromPublicKey(keyPair2));
			Assertions.assertNotSame(ecKeyPair, other1);
			Assertions.assertEquals(ecKeyPair, other1);
			Assertions.assertNotSame(ecKeyPair, other2);
			Assertions.assertNotEquals(ecKeyPair, other2);
		}

		@Test
		public void testHashCode() {
			ECKeyPair other1 = new ECKeyPair(keyPair1, getParamsFromPublicKey(keyPair1));
			ECKeyPair other2 = new ECKeyPair(keyPair2, getParamsFromPublicKey(keyPair2));
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
			this.ecKeyPair = new ECKeyPair(keyPair, getParamsFromPublicKey(keyPair));
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

	@Nested
	@DisplayName("With invalid public key...")
	public class WithInvalidPublicKey {

		private ECParameterSpec curveParams = Mockito.mock(ECParameterSpec.class);
		private EllipticCurve curve = Mockito.mock(EllipticCurve.class);
		private ECFieldFp field = Mockito.mock(ECFieldFp.class);
		private ECPublicKey publicKey = Mockito.mock(ECPublicKey.class);
		private ECPrivateKey privateKey = Mockito.mock(ECPrivateKey.class);
		private KeyPair keyPair = new KeyPair(publicKey, privateKey);

		@BeforeEach
		public void setup() {
			Mockito.doReturn(curve).when(curveParams).getCurve();
			Mockito.doReturn(field).when(curve).getField();
			Mockito.doReturn(BigInteger.ZERO).when(curve).getA();
			Mockito.doReturn(BigInteger.ZERO).when(curve).getB();
			Mockito.doReturn(1).when(curveParams).getCofactor();
			Mockito.doReturn(new ECPoint(BigInteger.ONE, BigInteger.ONE)).when(publicKey).getW();
			Mockito.doReturn(BigInteger.valueOf(2)).when(field).getP();
		}

		@Test
		public void testValid() {
			Assertions.assertDoesNotThrow(() -> new ECKeyPair(keyPair, curveParams));
		}

		@Test
		public void testUnsupportedCofactor() {
			Mockito.doReturn(2).when(curveParams).getCofactor();
			Assertions.assertThrows(IllegalArgumentException.class, () -> new ECKeyPair(keyPair, curveParams));
		}

		@Test
		public void testInfiniteW() {
			Mockito.doReturn(ECPoint.POINT_INFINITY).when(publicKey).getW();
			Assertions.assertThrows(IllegalArgumentException.class, () -> new ECKeyPair(keyPair, curveParams));
		}

		@ParameterizedTest
		@CsvSource(value = {
				"-1, 0",
				"0, -1",
				"2, 0",
				"0, 2",
		})
		public void testInvalidPoint(int x, int y) {
			Mockito.doReturn(new ECPoint(BigInteger.valueOf(x), BigInteger.valueOf(y))).when(publicKey).getW();
			Assertions.assertThrows(IllegalArgumentException.class, () -> new ECKeyPair(keyPair, curveParams));
		}

		@ParameterizedTest
		@CsvSource(value = {
				"1, 0",
				"0, 1",
		})
		public void testInvalidCurveCoefficients(int a, int b) {
			Mockito.doReturn(BigInteger.valueOf(a)).when(curve).getA();
			Mockito.doReturn(BigInteger.valueOf(b)).when(curve).getB();
			Assertions.assertThrows(IllegalArgumentException.class, () -> new ECKeyPair(keyPair, curveParams));
		}

	}


}