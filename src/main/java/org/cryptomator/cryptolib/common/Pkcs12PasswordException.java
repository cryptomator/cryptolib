package org.cryptomator.cryptolib.common;

/**
 * Loading from PKCS12 format failed due to wrong password.
 */
public class Pkcs12PasswordException extends Pkcs12Exception {

	protected Pkcs12PasswordException(Throwable cause) {
		super("Wrong password", cause);
	}

}
