package org.cryptomator.cryptolib;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

public final class Cryptors {

	/**
	 * @param secureRandom E.g. an {@link ReseedingSecureRandom} instance.
	 * @return A version 1 CryptorProvider
	 */
	public static CryptorProvider version1(SecureRandom secureRandom) {
		return new org.cryptomator.cryptolib.v1.CryptorProviderImpl(secureRandom);
	}

}
