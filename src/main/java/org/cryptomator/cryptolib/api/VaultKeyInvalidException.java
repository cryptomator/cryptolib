package org.cryptomator.cryptolib.api;

/**
 * Thrown when a vault configuration file can not be authenticated or decrypted with the provided key, password or recipient secret.
 */
public class VaultKeyInvalidException extends VaultConfigLoadException {

	public VaultKeyInvalidException(String message) {
		super(message);
	}

	public VaultKeyInvalidException(String message, Throwable cause) {
		super(message, cause);
	}

}
