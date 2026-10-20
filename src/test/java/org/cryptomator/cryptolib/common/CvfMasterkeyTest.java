package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.CvfMasterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;

class CvfMasterkeyTest {

	private byte[] raw;
	private CvfMasterkey masterkey;

	@BeforeEach
	void setup() {
		raw = new byte[64];
		for (byte b=0; b<raw.length; b++) {
			raw[b] = b;
		}
		masterkey = new CvfMasterkey(raw);
	}

	@Test
	void testGenerate() {
		SecureRandom csprng = Mockito.mock(SecureRandom.class);

		CvfMasterkey masterkey = CvfMasterkey.generate(csprng);

		Mockito.verify(csprng, Mockito.atLeastOnce()).nextBytes(Mockito.any());
		Assertions.assertNotNull(masterkey);
	}

	@Test
	void testFrom() {
		byte[] encKeyBytes = new byte[32];
		byte[] macKeyBytes = new byte[32];
		Arrays.fill(encKeyBytes, (byte) 0x55);
		Arrays.fill(macKeyBytes, (byte) 0x77);
		DestroyableSecretKey encKey = Mockito.mock(DestroyableSecretKey.class);
		DestroyableSecretKey macKey = Mockito.mock(DestroyableSecretKey.class);
		Mockito.when(encKey.getEncoded()).thenReturn(encKeyBytes);
		Mockito.when(macKey.getEncoded()).thenReturn(macKeyBytes);

		CvfMasterkey masterkey = CvfMasterkey.from(encKey, macKey);

		Assertions.assertNotNull(masterkey);
		Assertions.assertArrayEquals(encKeyBytes, masterkey.getEncKey().getEncoded());
		Assertions.assertArrayEquals(macKeyBytes, masterkey.getMacKey().getEncoded());
	}

	@Test
	void testGetEncKey() {
		SecretKey encKey = masterkey.getEncKey();

		Assertions.assertArrayEquals(Arrays.copyOfRange(raw, 0,32), encKey.getEncoded());
	}

	@Test
	void testGetMacKey() {
		SecretKey encKey = masterkey.getMacKey();

		Assertions.assertArrayEquals(Arrays.copyOfRange(raw, 32, 64), encKey.getEncoded());
	}

	@Test
	void testCopy() {
		byte[] raw = new byte[64];
		Arrays.fill(raw, (byte) 0x55);
		CvfMasterkey original = new CvfMasterkey(raw);

		CvfMasterkey copy = original.copy();

		Assertions.assertEquals(original, copy);
		copy.destroy();
		Assertions.assertNotEquals(original, copy);
	}

}