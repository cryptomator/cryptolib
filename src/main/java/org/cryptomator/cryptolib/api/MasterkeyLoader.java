package org.cryptomator.cryptolib.api;

import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.net.URI;

/**
 * CvfMasterkey loaders load keys to unlock Cryptomator vaults.
 *
 * @see MasterkeyFileAccess
 */
@FunctionalInterface
public interface MasterkeyLoader {

	/**
	 * Loads a master key. This might be a long-running operation, as it may require user input or expensive computations.
	 * <p>
	 * It is the caller's responsibility to destroy the returned {@link CvfMasterkey} after usage by calling {@link CvfMasterkey#destroy()}. This can easily be done using a try-with-resource block:
	 * <pre>
	 * {@code
	 * Masterkeyloader keyLoader;
	 * URI keyId;
	 * try (CvfMasterkey key = keyLoader.loadKey(keyId) ){
	 *     // Do stuff with the key
	 * }
	 * }
	 * </pre>
	 *
	 * @param keyId An URI uniquely identifying the source and identity of the key
	 * @return a {@link CvfMasterkey} object wrapping the raw key bytes. Must not be null
	 * @throws MasterkeyLoadingFailedException Thrown when it is impossible to fulfill the request
	 */
	CvfMasterkey loadKey(URI keyId) throws MasterkeyLoadingFailedException;

}
