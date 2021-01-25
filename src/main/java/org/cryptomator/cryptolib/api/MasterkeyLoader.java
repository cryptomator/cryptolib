package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.net.URI;

/**
 * Masterkey loaders load keys to unlock Cryptomator vaults.
 *
 * @see MasterkeyFileAccess
 */
public interface MasterkeyLoader {

	boolean supportsScheme(String scheme);

	/**
	 * Loads a master key. This might be a long-running operation, as it may require user input or expensive computations.
	 *
	 * @param keyId An URI uniquely identifying the source and identity of the key
	 * @return The raw key bytes. Must not be null
	 * @throws MasterkeyLoadingFailedException Thrown when it is impossible to fulfill the request
	 */
	Masterkey loadKey(URI keyId) throws MasterkeyLoadingFailedException;

}
