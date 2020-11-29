package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

public class MasterkeyTest {

	private SecretKey encKey;
	private SecretKey macKey;
	private Masterkey masterkey;

	@BeforeEach
	public void setup() {
		encKey = Mockito.mock(SecretKey.class);
		macKey = Mockito.mock(SecretKey.class);
		masterkey = new Masterkey(encKey, macKey);
	}

	@Test
	public void testCreateNew() {
		SecureRandom csprng = Mockito.mock(SecureRandom.class);

		Masterkey masterkey = Masterkey.createNew(csprng);

		Mockito.verify(csprng, Mockito.atLeastOnce()).nextBytes(Mockito.any());
		Assertions.assertNotNull(masterkey);
	}

	@ParameterizedTest
	@MethodSource("create64RandomBytes")
	public void testCreateFromRawKey(byte[] encoded) {
		Masterkey masterkey = Masterkey.createFromRaw(encoded);

		Assertions.assertNotNull(masterkey);
		Assertions.assertArrayEquals(encoded, masterkey.getEncoded());
	}

	static Stream<byte[]> create64RandomBytes() {
		Random rnd = new Random(42l);
		return Stream.generate(() -> {
			byte[] bytes = new byte[64];
			rnd.nextBytes(bytes);
			return bytes;
		}).limit(10);
	}

	@Test
	public void testGetEncKey() {
		SecretKey encKey = masterkey.getEncKey();

		Assertions.assertSame(this.encKey, encKey);
	}

	@Test
	public void testGetMacKey() {
		SecretKey macKey = masterkey.getMacKey();

		Assertions.assertSame(this.macKey, macKey);
	}

	@Test
	public void testDestroy() throws DestroyFailedException {
		masterkey.destroy();

		Mockito.verify(encKey).destroy();
		Mockito.verify(macKey).destroy();
	}

	@ParameterizedTest
	@CsvSource(value = {
			"false,true,false",
			"true,false,false",
			"false,false,false"
	})
	public void testIsNotDestroyed(boolean k1, boolean k2) {
		Mockito.when(encKey.isDestroyed()).thenReturn(k1);
		Mockito.when(macKey.isDestroyed()).thenReturn(k2);

		boolean destroyed = masterkey.isDestroyed();

		Assertions.assertFalse(destroyed);
	}

	@Test
	public void testIsDestroyed() {
		Mockito.when(encKey.isDestroyed()).thenReturn(true);
		Mockito.when(macKey.isDestroyed()).thenReturn(true);

		boolean destroyed = masterkey.isDestroyed();

		Assertions.assertTrue(destroyed);
	}

	@ParameterizedTest(name = "new Masterkey({0}, {1}).getEncoded() == {2}")
	@CsvSource(value = {
			"foo,bar,foobar",
			"foo,barbaz,foobarbaz",
			"foobar,baz,foobarbaz"
	})
	public void testGetEncoded(String k1, String k2, String combined) {
		Mockito.when(encKey.getEncoded()).thenReturn(k1.getBytes());
		Mockito.when(macKey.getEncoded()).thenReturn(k2.getBytes());

		byte[] raw = masterkey.getEncoded();

		Assertions.assertArrayEquals(combined.getBytes(), raw);
	}

}