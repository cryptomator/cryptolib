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

public interface FileContentCryptor {

	/**
	 * @return The number of cleartext bytes per chunk.
	 */
	int cleartextChunkSize();

	/**
	 * @return The number of ciphertext bytes per chunk.
	 */
	int ciphertextChunkSize();

	/**
	 * Encrypts a single chunk of cleartext.
	 * 
	 * @param cleartextChunk Content to be encrypted
	 * @param chunkNumber Number of the chunk to be encrypted
	 * @param header Header of the file, this chunk belongs to
	 * @return Encrypted content.
	 */
	ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header);

	/**
	 * Decrypts a single chunk of ciphertext.
	 * 
	 * @param ciphertextChunk Content to be decrypted
	 * @param chunkNumber Number of the chunk to be decrypted
	 * @param header Header of the file, this chunk belongs to
	 * @param authenticate Skip authentication by setting this flag to <code>false</code>. Should always be <code>true</code> by default.
	 * @return Decrypted content. Position is set to <code>0</code> and limit to the end of the chunk.
	 * @throws AuthenticationFailedException If authenticate is <code>true</code> and the given chunk does not match its MAC.
	 */
	ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException;

}
