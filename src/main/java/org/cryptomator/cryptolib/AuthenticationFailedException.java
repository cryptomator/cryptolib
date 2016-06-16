/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

public class AuthenticationFailedException extends CryptoException {

	AuthenticationFailedException() {
		super();
	}

	AuthenticationFailedException(String message) {
		super(message);
	}

	AuthenticationFailedException(Throwable cause) {
		super(cause);
	}

	AuthenticationFailedException(String message, Throwable cause) {
		super(message, cause);
	}

}
