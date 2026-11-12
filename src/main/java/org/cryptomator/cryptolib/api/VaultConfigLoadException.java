package org.cryptomator.cryptolib.api;

/**
 * Thrown when a vault configuration file can not be parsed or does not meet the format's structural requirements.
 */
public class VaultConfigLoadException extends CryptoException {

	public VaultConfigLoadException(String message) {
		super(message);
	}

	public VaultConfigLoadException(String message, Throwable cause) {
		super(message, cause);
	}

}
