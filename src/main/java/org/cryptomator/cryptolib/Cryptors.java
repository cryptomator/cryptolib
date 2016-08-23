/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib;

import java.security.SecureRandom;

import org.cryptomator.cryptolib.api.Cryptor;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.FileHeader;
import org.cryptomator.cryptolib.common.ReseedingSecureRandom;

public final class Cryptors {

	/**
	 * @param secureRandom E.g. an {@link ReseedingSecureRandom} instance.
	 * @return A version 1 CryptorProvider
	 */
	public static CryptorProvider version1(SecureRandom secureRandom) {
		return new org.cryptomator.cryptolib.v1.CryptorProviderImpl(secureRandom);
	}

	/**
	 * Calculates the size of the cleartext resulting from the given ciphertext decrypted with the given cryptor.
	 * 
	 * @param ciphertextSize Pure payload ciphertext. Not including the {@link FileHeader#getFilesize() length of the header}.
	 * @return Cleartext length of a <code>ciphertextSize</code>-sized ciphertext decrypted with <code>cryptor</code>.
	 */
	public static long cleartextSize(long ciphertextSize, Cryptor cryptor) {
		long cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
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
	 * @return Ciphertext length of a <code>cleartextSize</code>-sized cleartext encrypted with <code>cryptor</code>.
	 *         Not including the {@link FileHeader#getFilesize() length of the header}.
	 */
	public static long ciphertextSize(long cleartextSize, Cryptor cryptor) {
		long cleartextChunkSize = cryptor.fileContentCryptor().cleartextChunkSize();
		long ciphertextChunkSize = cryptor.fileContentCryptor().ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
		long additionalCleartextBytes = cleartextSize % cleartextChunkSize;
		long additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
		assert additionalCiphertextBytes >= 0;
		return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
	}

}
