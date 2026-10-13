package org.cryptomator.cryptolib.internal;

import com.google.common.base.Preconditions;

/**
 * Size and offset arithmetic for a chunked file format: a fixed-size header followed by chunks of equal size, the last one possibly shorter, optionally terminated by an empty EOF chunk.
 */
public final class FileLayout {

	private final int headerSize;
	private final int cleartextChunkSize;
	private final int ciphertextChunkSize;
	private final boolean eofChunk;

	/**
	 * @param headerSize Size of the encrypted header in bytes
	 * @param cleartextChunkSize Cleartext bytes per full chunk
	 * @param ciphertextChunkSize Ciphertext bytes per full chunk
	 * @param eofChunk Whether a file whose cleartext size is a multiple of {@code cleartextChunkSize} (including 0) ends with an additional empty chunk
	 */
	public FileLayout(int headerSize, int cleartextChunkSize, int ciphertextChunkSize, boolean eofChunk) {
		Preconditions.checkArgument(headerSize >= 0 && cleartextChunkSize > 0 && ciphertextChunkSize > cleartextChunkSize);
		this.headerSize = headerSize;
		this.cleartextChunkSize = cleartextChunkSize;
		this.ciphertextChunkSize = ciphertextChunkSize;
		this.eofChunk = eofChunk;
	}

	public int headerSize() {
		return headerSize;
	}

	public int cleartextChunkSize() {
		return cleartextChunkSize;
	}

	public int ciphertextChunkSize() {
		return ciphertextChunkSize;
	}

	public int chunkOverhead() {
		return ciphertextChunkSize - cleartextChunkSize;
	}

	public boolean hasEofChunk() {
		return eofChunk;
	}

	/**
	 * @param cleartextSize Size of the cleartext in bytes
	 * @return Size of the ciphertext file in bytes, including the header
	 */
	public long ciphertextSize(long cleartextSize) {
		Preconditions.checkArgument(cleartextSize >= 0, "expected cleartextSize to be positive, but was %s", cleartextSize);
		long fullChunks = cleartextSize / cleartextChunkSize;
		long remainder = cleartextSize % cleartextChunkSize;
		long result = headerSize + fullChunks * ciphertextChunkSize;
		if (remainder > 0) {
			result += remainder + chunkOverhead();
		} else if (eofChunk) {
			result += chunkOverhead();
		}
		return result;
	}

	/**
	 * @param ciphertextFileSize Size of the ciphertext file in bytes, including the header
	 * @return Size of the cleartext in bytes
	 * @throws IllegalArgumentException If no valid file can have the given size
	 */
	public long cleartextSize(long ciphertextFileSize) {
		Preconditions.checkArgument(ciphertextFileSize >= headerSize, "ciphertext file size %s is smaller than the header size %s", ciphertextFileSize, headerSize);
		long body = ciphertextFileSize - headerSize;
		long fullChunks = body / ciphertextChunkSize;
		long remainder = body % ciphertextChunkSize;
		if (remainder == 0) {
			if (eofChunk) {
				throw new IllegalArgumentException("Ciphertext file size " + ciphertextFileSize + " is invalid: missing EOF chunk");
			}
			return fullChunks * cleartextChunkSize;
		} else if (remainder < chunkOverhead()) {
			throw new IllegalArgumentException("Ciphertext file size " + ciphertextFileSize + " is invalid: truncated chunk");
		} else if (remainder == chunkOverhead()) {
			if (eofChunk) {
				return fullChunks * cleartextChunkSize;
			} else {
				throw new IllegalArgumentException("Ciphertext file size " + ciphertextFileSize + " is invalid: empty chunk");
			}
		} else {
			return fullChunks * cleartextChunkSize + remainder - chunkOverhead();
		}
	}

	/**
	 * @param cleartextSize Size of the cleartext in bytes
	 * @return Number of chunks a complete file of this size consists of, including the EOF chunk where applicable
	 */
	public long chunkCount(long cleartextSize) {
		Preconditions.checkArgument(cleartextSize >= 0);
		if (eofChunk) {
			return cleartextSize / cleartextChunkSize + 1;
		} else {
			return (cleartextSize + cleartextChunkSize - 1) / cleartextChunkSize;
		}
	}

	public long chunkIndex(long cleartextPosition) {
		Preconditions.checkArgument(cleartextPosition >= 0);
		return cleartextPosition / cleartextChunkSize;
	}

	public int offsetInChunk(long cleartextPosition) {
		Preconditions.checkArgument(cleartextPosition >= 0);
		return (int) (cleartextPosition % cleartextChunkSize);
	}

	public long ciphertextChunkOffset(long chunkIndex) {
		Preconditions.checkArgument(chunkIndex >= 0);
		return headerSize + chunkIndex * ciphertextChunkSize;
	}

	public long cleartextChunkOffset(long chunkIndex) {
		Preconditions.checkArgument(chunkIndex >= 0);
		return chunkIndex * cleartextChunkSize;
	}

	/**
	 * @param cleartextSize Size of the cleartext in bytes
	 * @param chunkIndex Index of a chunk
	 * @return Number of cleartext bytes in that chunk ({@code 0} for an EOF chunk), or {@code -1} if a file of this size has no such chunk
	 */
	public int cleartextChunkLength(long cleartextSize, long chunkIndex) {
		if (chunkIndex < 0 || chunkIndex >= chunkCount(cleartextSize)) {
			return -1;
		}
		long start = cleartextChunkOffset(chunkIndex);
		return (int) Math.min(cleartextChunkSize, cleartextSize - start);
	}

	/**
	 * @param cleartextSize Size of the cleartext in bytes
	 * @param chunkIndex Index of a chunk
	 * @return Number of ciphertext bytes of that chunk, or {@code -1} if a file of this size has no such chunk
	 */
	public int ciphertextChunkLength(long cleartextSize, long chunkIndex) {
		int cleartextLength = cleartextChunkLength(cleartextSize, chunkIndex);
		return cleartextLength < 0 ? -1 : cleartextLength + chunkOverhead();
	}

}
