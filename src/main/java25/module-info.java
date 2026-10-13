import org.cryptomator.cryptolib.api.CryptorProvider;

/**
 * This module provides the highlevel cryptographic API used by Cryptomator.
 *
 * @uses CryptorProvider See {@link CryptorProvider#forScheme(CryptorProvider.Scheme)}
 * @provides CryptorProvider Providers for {@link org.cryptomator.cryptolib.api.CryptorProvider.Scheme#SIV_CTRMAC SIV/CTR-then-MAC}
 * and {@link org.cryptomator.cryptolib.api.CryptorProvider.Scheme#SIV_GCM SIV/GCM}
 */
module org.cryptomator.cryptolib {
	requires org.bouncycastle.provider;
	requires org.bouncycastle.pkix;
	requires com.nimbusds.jose.jwt;
	requires org.cryptomator.siv;
	requires com.google.gson;
	requires transitive com.google.common;
	requires org.slf4j;

	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.common to com.google.gson;

	uses CryptorProvider;

	provides CryptorProvider
			with org.cryptomator.cryptolib.v1.CryptorProviderImpl, org.cryptomator.cryptolib.v2.CryptorProviderImpl;
}
