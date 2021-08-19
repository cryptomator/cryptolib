module org.cryptomator.cryptolib {
	requires org.cryptomator.siv;
	requires com.google.gson;
	requires com.google.common;
	requires org.slf4j;
	requires static org.bouncycastle.provider;
	requires static org.bouncycastle.pkix;

	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.common to com.google.gson;

	uses org.cryptomator.cryptolib.api.CryptorProvider;

	provides org.cryptomator.cryptolib.api.CryptorProvider
			with org.cryptomator.cryptolib.v1.CryptorProviderImpl, org.cryptomator.cryptolib.v2.CryptorProviderImpl;
}