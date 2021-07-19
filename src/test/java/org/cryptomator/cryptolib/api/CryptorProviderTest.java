package org.cryptomator.cryptolib.api;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class CryptorProviderTest {

	@DisplayName("CryptorProvider.forScheme(...)")
	@ParameterizedTest
	@EnumSource(CryptorProvider.Scheme.class)
	public void testForScheme(CryptorProvider.Scheme scheme) {
		CryptorProvider provider = CryptorProvider.forScheme(scheme);
		Assertions.assertNotNull(provider);
	}

}