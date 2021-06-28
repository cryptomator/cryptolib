/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

public interface FileHeader {

	/**
	 * Returns the value of a currently unused 64 bit field in the file header.
	 * <p>
	 * Formerly used for storing the plaintext file size.
	 *
	 * @return 64 bit integer for future use.
	 * @deprecated Don't rely on this method. It may be redefined any time.
	 */
	@Deprecated
	long getReserved();

	/**
	 * Sets the 64 bit field in the file header.
	 * <p>
	 * Formerly used for storing the plaintext file size.
	 *
	 * @param reserved 64 bit integer for future use
	 * @deprecated Don't rely on this method. It may be redefined any time.
	 */
	@Deprecated
	void setReserved(long reserved);

}
