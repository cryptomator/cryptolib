package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;

public class MasterkeyTest {

	private byte[] raw;
	private Masterkey masterkey;

	@BeforeEach
	public void setup() {
		raw = new byte[64];
		for (byte b=0; b<raw.length; b++) {
			raw[b] = b;
		}
		masterkey = new Masterkey(raw);
	}

	@Test
	public void testGenerate() {
		SecureRandom csprng = Mockito.mock(SecureRandom.class);

		Masterkey masterkey = Masterkey.generate(csprng);

		Mockito.verify(csprng, Mockito.atLeastOnce()).nextBytes(Mockito.any());
		Assertions.assertNotNull(masterkey);
	}

	@Test
	public void testGetEncKey() {
		SecretKey encKey = masterkey.getEncKey();

		Assertions.assertArrayEquals(Arrays.copyOfRange(raw, 0,32), encKey.getEncoded());
	}

	@Test
	public void testGetMacKey() {
		SecretKey encKey = masterkey.getMacKey();

		Assertions.assertArrayEquals(Arrays.copyOfRange(raw, 32, 64), encKey.getEncoded());
	}

	@Test
	public void testClone() {
		byte[] raw = new byte[64];
		Arrays.fill(raw, (byte) 0x55);
		Masterkey original = new Masterkey(raw);

		Masterkey clone = original.clone();

		Assertions.assertEquals(original, clone);
		clone.destroy();
		Assertions.assertNotEquals(original, clone);
	}

}