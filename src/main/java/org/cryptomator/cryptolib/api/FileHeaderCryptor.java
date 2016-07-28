/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import java.nio.ByteBuffer;

public interface FileHeaderCryptor {

	FileHeader create();

	int headerSize();

	/**
	 * @param header The header to encrypt.
	 * @return A buffer containing the encrypted header. The position of this buffer is <code>0</code> and its limit is at the end of the header.
	 */
	ByteBuffer encryptHeader(FileHeader header);

	FileHeader decryptHeader(ByteBuffer ciphertextHeaderBuf) throws AuthenticationFailedException;

}
