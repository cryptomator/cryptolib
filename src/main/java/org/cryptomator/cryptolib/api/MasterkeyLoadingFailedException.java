package org.cryptomator.cryptolib.api;

public class MasterkeyLoadingFailedException extends CryptoException {

	public MasterkeyLoadingFailedException(String message, Throwable cause) {
		super(message, cause);
	}

	public MasterkeyLoadingFailedException(String message) {
		super(message);
	}

}
