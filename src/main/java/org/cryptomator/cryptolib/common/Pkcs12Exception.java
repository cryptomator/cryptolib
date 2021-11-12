package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.CryptoException;

/**
 * Loading from or exporting to PKCS12 format failed.
 */
public class Pkcs12Exception extends CryptoException {

	protected Pkcs12Exception(String message, Throwable cause) {
		super(message, cause);
	}

}
