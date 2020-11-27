/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * This file is licensed under the terms of the MIT license.
 * See the LICENSE.txt file for more info.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

public abstract class CryptoException extends Exception {

	protected CryptoException() {
		super();
	}

	protected CryptoException(String message) {
		super(message);
	}

	protected CryptoException(String message, Throwable cause) {
		super(message, cause);
	}

}
