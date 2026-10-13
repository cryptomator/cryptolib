package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

@SuppressWarnings("resource")
public class DestroyableSecretKeyTest {

	@DisplayName("generate(...)")
	@ParameterizedTest(name = "keylen = {0}")
	@ValueSource(ints = {0, 16, 24, 32, 64, 777})
	public void testGenerateNew(int keylen) {
		byte[] keySrc = new byte[keylen];
		new Random(42).nextBytes(keySrc);
		SecureRandom csprng = Mockito.mock(SecureRandom.class);
		Mockito.doAnswer(invocation -> {
			byte[] keyDst = invocation.getArgument(0);
			assert keySrc.length == keyDst.length;
			System.arraycopy(keySrc, 0, keyDst, 0, keyDst.length);
			return null;
		}).when(csprng).nextBytes(Mockito.any());

		DestroyableSecretKey key = DestroyableSecretKey.generate(csprng, "TEST", keylen);

		Assertions.assertNotNull(key);
		Assertions.assertArrayEquals(keySrc, key.getEncoded());
		Mockito.verify(csprng).nextBytes(Mockito.any());
	}

	@Test
	public void testConstructorFailsForInvalidAlgorithm() {
		Assertions.assertThrows(NullPointerException.class, () -> {
			new DestroyableSecretKey(new byte[16], null);
		});
	}

	@Test
	public void testConstructorFailsForInvalidLength() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new DestroyableSecretKey(new byte[16], 0, -1, "TEST");
		});
	}

	@Test
	public void testConstructorFailsForInvalidOffset() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new DestroyableSecretKey(new byte[16], -1, 16, "TEST");
		});
	}

	@Test
	public void testConstructorFailsForInvalidLengthAndOffset() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			new DestroyableSecretKey(new byte[16], 8, 16, "TEST");
		});
	}

	@Test
	public void testConstructorCreatesLocalCopy() {
		byte[] orig = "hello".getBytes();
		DestroyableSecretKey key = new DestroyableSecretKey(orig, "TEST");
		Arrays.fill(orig, (byte) 0x00);
		Assertions.assertArrayEquals("hello".getBytes(), key.getEncoded());
	}

	@Test
	public void testConstructorCopiesKey() {
		byte[] empty = new byte[32];
		byte[] rawKey = new byte[32];
		new Random(42).nextBytes(rawKey);
		Assumptions.assumeFalse(Arrays.equals(empty, rawKey));

		DestroyableSecretKey key = new DestroyableSecretKey(rawKey, "TEST");

		Assertions.assertArrayEquals(rawKey, key.getEncoded());
		Arrays.fill(rawKey, (byte) 0x00);
		Assertions.assertFalse(Arrays.equals(empty, key.getEncoded()));
	}

	@Nested
	@DisplayName("An undestroyed key...")
	public class WithUndestroyed {

		private byte[] rawKey;
		private DestroyableSecretKey key;

		@BeforeEach
		public void setup() {
			this.rawKey = new byte[32];
			new Random(42).nextBytes(rawKey);
			this.key = new DestroyableSecretKey(rawKey, "EXAMPLE");
		}

		@Test
		@DisplayName("isDestroyed() returns false")
		public void testIsDestroyed() {
			Assertions.assertFalse(key.isDestroyed());
		}

		@Test
		@DisplayName("equals(empty key) returns false")
		public void testEquals() {
			DestroyableSecretKey emptyKey = new DestroyableSecretKey(new byte[32], "EXAMPLE");

			// hashcode _may_ collide, though
			Assertions.assertNotEquals(emptyKey, key);
		}

		@Test
		@DisplayName("getAlgorithm() returns algorithm")
		public void testGetAlgorithm() {
			Assertions.assertEquals("EXAMPLE", key.getAlgorithm());
		}

		@Test
		@DisplayName("getFormat() returns 'RAW'")
		public void testGetFormat() {
			Assertions.assertEquals("RAW", key.getFormat());
		}

		@Test
		@DisplayName("getEncoded() returns raw key")
		public void testGetEncoded() {
			Assertions.assertArrayEquals(rawKey, key.getEncoded());
		}

		@Test
		@DisplayName("copy() returns equal copy")
		public void testCopy() {
			DestroyableSecretKey copy = key.copy();

			Assertions.assertEquals(key, copy);
			Assertions.assertNotSame(key, copy);
		}

		@Test
		@DisplayName("close() destroys key")
		public void testClose() {
			key.close();

			Assertions.assertTrue(key.isDestroyed());
		}

		@Nested
		@DisplayName("After destroy()...")
		public class WithDestroyed {

			@BeforeEach
			public void setup() {
				key.close();
			}

			@Test
			@DisplayName("isDestroyed() returns true")
			public void testIsDestroyed() {
				Assertions.assertTrue(key.isDestroyed());
			}

			@Test
			@DisplayName("equals(empty key) returns true")
			public void testEquals() {
				DestroyableSecretKey emptyKey = new DestroyableSecretKey(new byte[32], "EXAMPLE");

				Assertions.assertEquals(emptyKey.hashCode(), key.hashCode());
				Assertions.assertEquals(emptyKey, key);
			}

			@Test
			@DisplayName("getAlgorithm() throws IllegalStateException")
			public void testGetAlgorithm() {
				Assertions.assertThrows(IllegalStateException.class, key::getAlgorithm);
			}

			@Test
			@DisplayName("getFormat() throws IllegalStateException")
			public void testGetFormat() {
				Assertions.assertThrows(IllegalStateException.class, key::getFormat);
			}

			@Test
			@DisplayName("getEncoded() throws IllegalStateException")
			public void testGetEncoded() {
				Assertions.assertThrows(IllegalStateException.class, key::getEncoded);
			}

			@Test
			@DisplayName("copy() throws IllegalStateException")
			public void testCopy() {
				Assertions.assertThrows(IllegalStateException.class, key::copy);
			}

		}

	}

}