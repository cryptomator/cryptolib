package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.MasterkeyLoadingFailedException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.crypto.SecretKey;
import javax.security.auth.DestroyFailedException;

public class MasterkeyFileLoaderTest {

	@Test
	public void testLoadedKeySurvivesLoader() throws MasterkeyLoadingFailedException, DestroyFailedException {
		SecretKey encKey = Mockito.mock(SecretKey.class);
		SecretKey macKey = Mockito.mock(SecretKey.class);
		Mockito.when(encKey.getEncoded()).thenReturn(new byte[32]);
		Mockito.when(encKey.getAlgorithm()).thenReturn("AES");
		Mockito.when(macKey.getEncoded()).thenReturn(new byte[32]);
		Mockito.when(macKey.getAlgorithm()).thenReturn("HmacSHA256");

		Masterkey masterkey;
		try (MasterkeyFileLoader loader = new MasterkeyFileLoader(encKey, macKey)) {
			masterkey = loader.loadKey(MasterkeyFileLoader.KEY_ID);
		}

		Mockito.verify(encKey).destroy();
		Mockito.verify(macKey).destroy();
		Assertions.assertFalse(masterkey.isDestroyed());
	}

}