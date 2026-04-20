package org.cryptomator.cryptolib.v3;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.RevolvingMasterkey;
import org.cryptomator.cryptolib.common.SecureRandomMock;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.security.SecureRandom;

public class CryptorProviderImplTest {

	private static final SecureRandom RANDOM_MOCK = SecureRandomMock.NULL_RANDOM;

	@Test
	public void testProvide() {
		RevolvingMasterkey masterkey = Mockito.mock(RevolvingMasterkey.class);
		CryptorProvider provider = new CryptorProviderImpl();
		Assertions.assertInstanceOf(CryptorImpl.class, provider.provide(masterkey, RANDOM_MOCK));
	}

}
