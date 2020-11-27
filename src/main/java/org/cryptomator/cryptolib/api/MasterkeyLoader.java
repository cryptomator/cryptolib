package org.cryptomator.cryptolib.api;

/**
 * Masterkey loaders load keys to unlock Cryptomator vaults.
 *
 * @see org.cryptomator.cryptolib.common.MasterkeyFileLoader
 */
@FunctionalInterface
public interface MasterkeyLoader {

	/**
	 * Loads a master key. This might be a long-running operation, as it may require user input or expensive computations.
	 *
	 * @param keyId a string uniquely identifying the source of the key and its identity, if multiple keys can be obtained from the same source
	 * @return The raw key bytes. Must not be null
	 * @throws MasterkeyLoadingFailedException Thrown when it is impossible to fulfill the request
	 */
	Masterkey loadKey(String keyId) throws MasterkeyLoadingFailedException;

}
