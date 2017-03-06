package org.cryptomator.cryptolib.v1;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class Version1CryptorModuleTest {

	@Test(expected = IllegalStateException.class)
	public void testProvideCryptorProviderWithRestrictedKeyLength() {
		Version1CryptorModule module = Mockito.mock(Version1CryptorModule.class);
		Mockito.when(module.provideCryptorProvider(Mockito.any(SecureRandom.class))).thenCallRealMethod();
		Mockito.when(module.isRequiredKeyLengthAllowed()).thenReturn(false);
		module.provideCryptorProvider(SecureRandomMock.NULL_RANDOM);
	}

	@Test
	public void testProvideCryptorProvider() {
		Version1CryptorModule module = Mockito.mock(Version1CryptorModule.class);
		Mockito.when(module.provideCryptorProvider(Mockito.any(SecureRandom.class))).thenCallRealMethod();
		Mockito.when(module.isRequiredKeyLengthAllowed()).thenReturn(true);
		CryptorProvider provider = module.provideCryptorProvider(SecureRandomMock.NULL_RANDOM);
		Assert.assertNotNull(provider);
	}

}
