module org.cryptomator.cryptolib {
	requires static org.bouncycastle.provider; // will be shaded
	requires static org.bouncycastle.pkix; // will be shaded
	requires jdk.crypto.ec; // required at runtime for ECC
	requires org.cryptomator.siv;
	requires com.google.gson;
	requires transitive com.google.common;
	requires org.slf4j;

	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.common to com.google.gson;

	uses org.cryptomator.cryptolib.api.CryptorProvider;

	provides org.cryptomator.cryptolib.api.CryptorProvider
			with org.cryptomator.cryptolib.v1.CryptorProviderImpl, org.cryptomator.cryptolib.v2.CryptorProviderImpl;
}