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

import static com.google.common.base.Preconditions.checkArgument;

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

	/**
	 * Calculates the size of the cleartext resulting from the given ciphertext decrypted with the given cryptor.
	 *
	 * @param ciphertextSize Length of encrypted payload. Not including the {@link FileHeaderCryptor#headerSize() length of the header}.
	 * @return Cleartext length of a <code>ciphertextSize</code>-sized ciphertext decrypted with <code>cryptor</code>.
	 */
	default long cleartextSize(long ciphertextSize) {
		checkArgument(ciphertextSize >= 0, "expected ciphertextSize to be positive, but was %s", ciphertextSize);
		long cleartextChunkSize = fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = fileContentCryptor().ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = ciphertextSize / ciphertextChunkSize; // floor by int-truncation
		long additionalCiphertextBytes = ciphertextSize % ciphertextChunkSize;
		if (additionalCiphertextBytes > 0 && additionalCiphertextBytes <= overheadPerChunk) {
			throw new IllegalArgumentException("Method not defined for input value " + ciphertextSize);
		}
		long additionalCleartextBytes = (additionalCiphertextBytes == 0) ? 0 : additionalCiphertextBytes - overheadPerChunk;
		assert additionalCleartextBytes >= 0;
		return cleartextChunkSize * numFullChunks + additionalCleartextBytes;
	}

	/**
	 * Calculates the size of the ciphertext resulting from the given cleartext encrypted with the given cryptor.
	 *
	 * @param cleartextSize Length of a unencrypted payload.
	 * @return Ciphertext length of a <code>cleartextSize</code>-sized cleartext encrypted with <code>cryptor</code>.
	 * Not including the {@link FileHeader#getFilesize() length of the header}.
	 */
	default long ciphertextSize(long cleartextSize) {
		checkArgument(cleartextSize >= 0, "expected cleartextSize to be positive, but was %s", cleartextSize);
		long cleartextChunkSize = fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = fileContentCryptor().ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
		long additionalCleartextBytes = cleartextSize % cleartextChunkSize;
		long additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
		assert additionalCiphertextBytes >= 0;
		return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
	}

}
