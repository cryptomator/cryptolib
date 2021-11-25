/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;

public interface Cryptor extends Destroyable, AutoCloseable {

	FileContentCryptor fileContentCryptor();

	FileHeaderCryptor fileHeaderCryptor();

	FileNameCryptor fileNameCryptor();

	@Override
	void destroy();

	/**
	 * Calls {@link #destroy()}.
	 */
	@Override
	default void close() {
		destroy();
	}

}
