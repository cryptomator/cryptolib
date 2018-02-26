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
	 * @deprecated No longer supported since vault version 5. Use {@link org.cryptomator.cryptolib.Cryptors#cleartextSize(long, Cryptor)} to calculate the cleartext size from the ciphertext size
	 * @return file size stored in file header
	 */
	@Deprecated
	long getFilesize();

	/**
	 * @deprecated No longer used since vault version 5. Data stored in the header might get a different purpose in future versions.
	 * @param filesize number of bytes
	 */
	@Deprecated
	void setFilesize(long filesize);

}
