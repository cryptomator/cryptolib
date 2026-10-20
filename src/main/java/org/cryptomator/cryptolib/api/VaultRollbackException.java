package org.cryptomator.cryptolib.api;

/**
 * Thrown when a {@code vault.uvf} lacks a seed the application has seen before, i.e. an older or forged version of the file was presented (see seed pinning in the UVF specification).
 */
public class VaultRollbackException extends VaultConfigLoadException {

	public VaultRollbackException(String message) {
		super(message);
	}

}
