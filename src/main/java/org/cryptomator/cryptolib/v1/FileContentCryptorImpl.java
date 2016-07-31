/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.v1;

import java.nio.ByteBuffer;
import java.security.SecureRandom;

import javax.crypto.SecretKey;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.FileContentCryptor;
import org.cryptomator.cryptolib.api.FileHeader;

class FileContentCryptorImpl implements FileContentCryptor {

	private final SecretKey macKey;
	private final SecureRandom random;

	FileContentCryptorImpl(SecretKey macKey, SecureRandom random) {
		this.macKey = macKey;
		this.random = random;
	}

	@Override
	public int cleartextChunkSize() {
		return Constants.PAYLOAD_SIZE;
	}

	@Override
	public int ciphertextChunkSize() {
		return Constants.CHUNK_SIZE;
	}

	@Override
	public ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header) {
		if (cleartextChunk.remaining() == 0 || cleartextChunk.remaining() > Constants.PAYLOAD_SIZE) {
			throw new IllegalArgumentException("Invalid chunk");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		return FileContentChunks.encryptChunk(cleartextChunk.asReadOnlyBuffer(), chunkNumber, headerImpl.getNonce(), headerImpl.getPayload().getContentKey(), macKey, random);
	}

	@Override
	public ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException {
		if (ciphertextChunk.remaining() == 0 || ciphertextChunk.remaining() > Constants.CHUNK_SIZE) {
			throw new IllegalArgumentException("Invalid chunk");
		}
		FileHeaderImpl headerImpl = FileHeaderImpl.cast(header);
		if (authenticate && !FileContentChunks.checkChunkMac(macKey, headerImpl.getNonce(), chunkNumber, ciphertextChunk.asReadOnlyBuffer())) {
			throw new AuthenticationFailedException("Authentication of chunk " + chunkNumber + " failed.");
		} else {
			return FileContentChunks.decryptChunk(ciphertextChunk.asReadOnlyBuffer(), headerImpl.getPayload().getContentKey());
		}
	}

}
