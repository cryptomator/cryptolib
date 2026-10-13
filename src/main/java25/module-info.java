/**
 * This module provides the highlevel cryptographic API used by Cryptomator: everything about a vault except the file I/O.
 * <p>
 * Entry point is {@link org.cryptomator.cryptolib.api.LockedVault#parse(byte[])}.
 */
module org.cryptomator.cryptolib {
	requires org.bouncycastle.provider;
	requires org.bouncycastle.pkix;
	requires com.nimbusds.jose.jwt;
	requires org.cryptomator.siv;
	requires com.google.gson;
	requires com.google.common;
	requires org.slf4j;

	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.common to com.google.gson;
}
