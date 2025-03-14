package org.cryptomator.cryptolib.api;

import java.nio.ByteBuffer;

import static com.google.common.base.Preconditions.checkArgument;

public interface FileContentCryptor {

	/**
	 * @return <code>true</code> if it is technically possible to decrypt unauthentic ciphertext
	 */
	boolean canSkipAuthentication();

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
	 * @param cleartextChunk Content to be encrypted (starting at the buffer's current position, ending at the buffer's limit)
	 * @param chunkNumber Number of the chunk to be encrypted
	 * @param header Header of the file, this chunk belongs to
	 * @return Encrypted content. Position is set to <code>0</code> and limit to the end of the chunk.
	 */
	ByteBuffer encryptChunk(ByteBuffer cleartextChunk, long chunkNumber, FileHeader header);

	/**
	 * Encrypts a single chunk of cleartext.
	 *
	 * @param cleartextChunk Content to be encrypted (starting at the buffer's current position, ending at the buffer's limit)
	 * @param ciphertextChunk Encrypted content buffer (with at least {@link #ciphertextChunkSize()} remaining bytes)
	 * @param chunkNumber Number of the chunk to be encrypted
	 * @param header Header of the file, this chunk belongs to
	 */
	void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header);

	/**
	 * Decrypts a single chunk of ciphertext.
	 * 
	 * @param ciphertextChunk Content to be decrypted (starting at the buffer's current position, ending at the buffer's limit)
	 * @param chunkNumber Number of the chunk to be decrypted
	 * @param header Header of the file, this chunk belongs to
	 * @param authenticate Skip authentication by setting this flag to <code>false</code>. Should always be <code>true</code> by default.
	 * @return Decrypted content. Position is set to <code>0</code> and limit to the end of the chunk.
	 * @throws AuthenticationFailedException If authenticate is <code>true</code> and the given chunk does not match its MAC.
	 * @throws UnsupportedOperationException If authenticate is <code>false</code> but this cryptor {@link #canSkipAuthentication() can not skip authentication}.
	 */
	ByteBuffer decryptChunk(ByteBuffer ciphertextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException;

	/**
	 * Decrypts a single chunk of ciphertext.
	 *
	 * @param ciphertextChunk Content to be decrypted (starting at the buffer's current position, ending at the buffer's limit)
	 * @param cleartextChunk Buffer for decrypted chunk (with at least {@link #cleartextChunkSize()} remaining bytes)
	 * @param chunkNumber Number of the chunk to be decrypted
	 * @param header Header of the file, this chunk belongs to
	 * @param authenticate Skip authentication by setting this flag to <code>false</code>. Should always be <code>true</code> by default.
	 * @throws AuthenticationFailedException If authenticate is <code>true</code> and the given chunk does not match its MAC.
	 * @throws UnsupportedOperationException If authenticate is <code>false</code> but this cryptor {@link #canSkipAuthentication() can not skip authentication}.
	 */
	void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkNumber, FileHeader header, boolean authenticate) throws AuthenticationFailedException;

	/**
	 * Calculates the size of the cleartext resulting from the given ciphertext decrypted with the given cryptor.
	 *
	 * @param ciphertextSize Length of encrypted payload. Not including the {@link FileHeaderCryptor#headerSize() length of the header}.
	 * @return Cleartext length of a <code>ciphertextSize</code>-sized ciphertext decrypted with <code>cryptor</code>.
	 */
	default long cleartextSize(long ciphertextSize) {
		checkArgument(ciphertextSize >= 0, "expected ciphertextSize to be positive, but was %s", ciphertextSize);
		long cleartextChunkSize = cleartextChunkSize();
		long ciphertextChunkSize = ciphertextChunkSize();
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
	 * Not including the length of the header.
	 */
	default long ciphertextSize(long cleartextSize) {
		checkArgument(cleartextSize >= 0, "expected cleartextSize to be positive, but was %s", cleartextSize);
		long cleartextChunkSize = cleartextChunkSize();
		long ciphertextChunkSize = ciphertextChunkSize();
		long overheadPerChunk = ciphertextChunkSize - cleartextChunkSize;
		long numFullChunks = cleartextSize / cleartextChunkSize; // floor by int-truncation
		long additionalCleartextBytes = cleartextSize % cleartextChunkSize;
		long additionalCiphertextBytes = (additionalCleartextBytes == 0) ? 0 : additionalCleartextBytes + overheadPerChunk;
		assert additionalCiphertextBytes >= 0;
		return ciphertextChunkSize * numFullChunks + additionalCiphertextBytes;
	}

}
