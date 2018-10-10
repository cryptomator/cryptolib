/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.ByteBuffers;

public class DecryptingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final Cryptor cryptor;
	private final boolean authenticate;
	private ByteBuffer cleartextChunk;
	private FileHeader header;
	private boolean reachedEof = false;
	private long chunk = 0;

	public DecryptingReadableByteChannel(ReadableByteChannel src, Cryptor cryptor, boolean authenticate) {
		this.delegate = src;
		this.cryptor = cryptor;
		this.authenticate = authenticate;
		this.cleartextChunk = ByteBuffer.allocate(0); // empty buffer will trigger loadNextCleartextChunk() on first access.
	}

	@Override
	public boolean isOpen() {
		return delegate.isOpen();
	}

	@Override
	public void close() throws IOException {
		delegate.close();
	}

	@Override
	public synchronized int read(ByteBuffer dst) throws IOException {
		loadHeaderIfNecessary();
		if (reachedEof) {
			return -1;
		} else {
			return readInternal(dst);
		}
	}

	private int readInternal(ByteBuffer dst) throws IOException {
		assert header != null : "header must be initialized";

		int result = 0;
		while (dst.hasRemaining() && !reachedEof) {
			if (cleartextChunk.hasRemaining() || loadNextCleartextChunk()) {
				result += ByteBuffers.copy(cleartextChunk, dst);
			} else {
				assert reachedEof : "no further cleartext available";
			}
		}
		return result;
	}

	private void loadHeaderIfNecessary() throws IOException {
		if (header == null) {
			ByteBuffer headerBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
			int read = delegate.read(headerBuf);
			if (read != headerBuf.capacity()) {
				throw new IllegalArgumentException("Unable to read header from channel.");
			}
			headerBuf.flip();
			header = cryptor.fileHeaderCryptor().decryptHeader(headerBuf);
		}
	}

	private boolean loadNextCleartextChunk() throws IOException {
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
		int read = delegate.read(ciphertextChunk);
		if (read == -1) {
			reachedEof = true;
			return false;
		} else {
			ciphertextChunk.flip();
			cleartextChunk = cryptor.fileContentCryptor().decryptChunk(ciphertextChunk, chunk++, header, authenticate);
			return true;
		}
	}

}
