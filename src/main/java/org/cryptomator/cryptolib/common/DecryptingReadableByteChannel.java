/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.common;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.FileHeader;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

public class DecryptingReadableByteChannel implements ReadableByteChannel {

	private final ReadableByteChannel delegate;
	private final Cryptor cryptor;
	private final boolean authenticate;
	private final boolean validateStructure;
	private ByteBuffer cleartextChunk;
	private FileHeader header;
	private boolean reachedEof;
	private boolean readEmptyChunk;
	private long chunk;
	private long ciphertextBodyBytes;
	private long lastChunkCiphertextBytes;
	private long cleartextBytes;

	/**
	 * Creates a DecryptingReadableByteChannel that decrypts a whole ciphertext file beginning at its first byte.
	 * <p>
	 * Reading the whole file allows validating its structure: once the end of the ciphertext is reached, the number of ciphertext bytes read
	 * must correspond to the number of cleartext bytes produced according to {@link org.cryptomator.cryptolib.api.FileContentCryptor#cleartextSize(long)},
	 * which e.g. detects a missing EOF chunk in Universal Vault Format.
	 *
	 * @param src          A ciphertext channel positioned at the begin of the file header
	 * @param cryptor      The cryptor to use
	 * @param authenticate Set to <code>false</code> to skip ciphertext authentication (may not be supported)
	 */
	public DecryptingReadableByteChannel(ReadableByteChannel src, Cryptor cryptor, boolean authenticate) {
		this(src, cryptor, authenticate, null, 0);
	}

	/**
	 * Creates a DecryptingReadableByteChannel with a previously read header, allowing to start decryption at any chunk.
	 * <p>
	 * When starting at a chunk other than the first, the structure of the file (e.g. the presence of the EOF chunk in Universal Vault Format)
	 * cannot be validated by this channel; callers must do so themselves, e.g. via {@link org.cryptomator.cryptolib.api.FileContentCryptor#cleartextSize(long)}.
	 *
	 * @param src          A ciphertext channel positioned at the beginning of the given <code>firstChunk</code>
	 * @param cryptor      The cryptor to use
	 * @param authenticate Set to <code>false</code> to skip ciphertext authentication (may not be supported)
	 * @param header       The file's header
	 * @param firstChunk   The index of the chunk at which the <code>src</code> channel is positioned
	 */
	public DecryptingReadableByteChannel(ReadableByteChannel src, Cryptor cryptor, boolean authenticate, FileHeader header, long firstChunk) {
		this.delegate = src;
		this.cryptor = cryptor;
		this.authenticate = authenticate;
		this.validateStructure = firstChunk == 0;
		this.cleartextChunk = ByteBuffer.allocate(0); // empty buffer will trigger loadNextCleartextChunk() on first access.
		this.header = header;
		this.reachedEof = false;
		this.readEmptyChunk = false;
		this.chunk = firstChunk;
		this.ciphertextBodyBytes = 0;
		this.lastChunkCiphertextBytes = 0;
		this.cleartextBytes = 0;
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
		try {
			loadHeaderIfNecessary();
			if (reachedEof) {
				return -1;
			} else {
				return readInternal(dst);
			}
		} catch (AuthenticationFailedException e) {
			throw new IOException("Unauthentic ciphertext", e);
		}
	}

	private int readInternal(ByteBuffer dst) throws IOException, AuthenticationFailedException {
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

	private void loadHeaderIfNecessary() throws IOException, AuthenticationFailedException {
		if (header == null) {
			ByteBuffer headerBuf = ByteBuffer.allocate(cryptor.fileHeaderCryptor().headerSize());
			int read = ByteBuffers.fill(delegate, headerBuf);
			if (read != headerBuf.capacity()) {
				throw new EOFException("Unable to read header from channel.");
			}
			headerBuf.flip();
			header = cryptor.fileHeaderCryptor().decryptHeader(headerBuf);
		}
	}

	private boolean loadNextCleartextChunk() throws IOException, AuthenticationFailedException {
		ByteBuffer ciphertextChunk = ByteBuffer.allocate(cryptor.fileContentCryptor().ciphertextChunkSize());
		int read = ByteBuffers.fill(delegate, ciphertextChunk);
		if (read == 0) {
			reachedEof = true;
			validateStructureIfPossible();
			return false;
		} else if (readEmptyChunk) {
			// an empty chunk is only valid as the final chunk (the EOF chunk), everything else indicates a reordered or spliced ciphertext
			throw new AuthenticationFailedException("Empty chunk in non-final position " + (chunk - 1));
		} else {
			ciphertextChunk.flip();
			ciphertextBodyBytes += read;
			lastChunkCiphertextBytes = read;
			cleartextChunk = cryptor.fileContentCryptor().decryptChunk(ciphertextChunk, chunk++, header, authenticate);
			cleartextBytes += cleartextChunk.remaining();
			readEmptyChunk = !cleartextChunk.hasRemaining();
			return true;
		}
	}

	// if the whole file has been read, the ciphertext size must be consistent with the number of chunks and their sizes, see FileContentCryptor#cleartextSize(long)
	private void validateStructureIfPossible() throws AuthenticationFailedException {
		if (!validateStructure) {
			return;
		}
		long expectedCleartextBytes;
		try {
			expectedCleartextBytes = cryptor.fileContentCryptor().cleartextSize(ciphertextBodyBytes);
		} catch (IllegalArgumentException e) {
			if (readEmptyChunk && isValidWithoutEmptyFinalChunk()) {
				// formats without an EOF chunk (Cryptomator Vault Format) don't account for the empty final chunk written by EncryptingWritableByteChannel; it has been authenticated, so it is harmless
				return;
			}
			throw new AuthenticationFailedException("Invalid ciphertext structure", e);
		}
		if (expectedCleartextBytes != cleartextBytes) {
			throw new AuthenticationFailedException("Ciphertext size " + ciphertextBodyBytes + " does not match " + cleartextBytes + " bytes of decrypted content");
		}
	}

	private boolean isValidWithoutEmptyFinalChunk() {
		try {
			return cryptor.fileContentCryptor().cleartextSize(ciphertextBodyBytes - lastChunkCiphertextBytes) == cleartextBytes;
		} catch (IllegalArgumentException e) {
			return false;
		}
	}

}
