package org.cryptomator.cryptolib.api;

import javax.security.auth.Destroyable;
import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * One open file of a vault: its header, the file key and the current cleartext size.
 * <p>
 * The high-level {@link #read}, {@link #write} and {@link #truncate} operations work on cleartext positions and access the ciphertext exclusively through the given callbacks; nothing is
 * cached. The chunk layer below them is for callers that maintain their own chunk cache. All buffers are provided by the caller; no method allocates and returns a buffer. The file holds
 * key material and must be {@link #destroy() destroyed} (or closed) when no longer needed.
 */
public interface VaultFile extends Destroyable, AutoCloseable {

	/**
	 * @return A read-only view of the encrypted header; identical on every call, as the header is encrypted exactly once
	 */
	ByteBuffer encryptedHeader();

	/**
	 * @return The id of the key revision (seed) this file's header was encrypted with; {@code 0} for Cryptomator Vault Format 8
	 */
	int seedId();

	/**
	 * @return The current cleartext size of the file in bytes
	 */
	long size();

	// HIGH LEVEL

	/**
	 * Reads cleartext starting at the given position.
	 *
	 * @param cleartextPosition Position within the cleartext
	 * @param dst Buffer to fill with cleartext; fewer bytes than {@code dst.remaining()} may be read
	 * @param ciphertextReader Reads the ciphertext
	 * @return Number of bytes read, or {@code -1} if {@code cleartextPosition} is at or beyond {@link #size()}
	 * @throws IOException If the reader fails
	 * @throws AuthenticationFailedException If a chunk is unauthentic
	 */
	int read(long cleartextPosition, ByteBuffer dst, CiphertextReader ciphertextReader) throws IOException, AuthenticationFailedException;

	/**
	 * Writes cleartext at the given position, growing the file if necessary and zero-filling any gap beyond the current {@link #size()}.
	 * <p>
	 * Partially overwritten chunks are read, authenticated, modified and re-encrypted. The header is written on the first write of a newly created file.
	 *
	 * @param cleartextPosition Position within the cleartext
	 * @param src Buffer whose remaining bytes are written
	 * @param ciphertextReader Reads chunks that are partially overwritten
	 * @param ciphertextWriter Writes the resulting ciphertext
	 * @return Number of bytes written, always {@code src.remaining()} at the time of the call
	 * @throws IOException If the reader or writer fails
	 * @throws AuthenticationFailedException If a partially overwritten chunk is unauthentic
	 */
	int write(long cleartextPosition, ByteBuffer src, CiphertextReader ciphertextReader, CiphertextWriter ciphertextWriter) throws IOException, AuthenticationFailedException;

	/**
	 * Shrinks the file to the given cleartext size, re-encrypting the new last chunk.
	 * <p>
	 * This method does not shorten the ciphertext file itself; after it returns, the caller must truncate the ciphertext to {@link UnlockedVault#ciphertextSize(long) ciphertextSize(newSize)}.
	 *
	 * @param newSize New cleartext size; must not exceed the current {@link #size()}
	 * @param ciphertextReader Reads the chunk that becomes the last one
	 * @param ciphertextWriter Writes the re-encrypted last chunk
	 * @throws IOException If the reader or writer fails
	 * @throws AuthenticationFailedException If the chunk is unauthentic
	 */
	void truncate(long newSize, CiphertextReader ciphertextReader, CiphertextWriter ciphertextWriter) throws IOException, AuthenticationFailedException;

	// CHUNK LAYER

	/**
	 * @param cleartextPosition Position within the cleartext
	 * @return Index of the chunk containing that position
	 */
	long chunkIndex(long cleartextPosition);

	/**
	 * @param cleartextPosition Position within the cleartext
	 * @return Offset of that position within its chunk's cleartext
	 */
	int offsetInChunk(long cleartextPosition);

	/**
	 * @param chunkIndex Index of a chunk
	 * @return Position of that chunk's ciphertext within the ciphertext file
	 */
	long ciphertextChunkOffset(long chunkIndex);

	/**
	 * @param chunkIndex Index of a chunk
	 * @return Position of that chunk's first byte within the cleartext
	 */
	long cleartextChunkOffset(long chunkIndex);

	/**
	 * Computes how many chunks a complete file of the given cleartext size consists of, including a trailing empty chunk where the format requires one.
	 *
	 * @param cleartextSize Size of the cleartext in bytes
	 * @return Number of chunks
	 */
	long chunkCount(long cleartextSize);

	/**
	 * Encrypts one chunk.
	 *
	 * @param cleartextChunk Cleartext from the buffer's position to its limit; at most {@link UnlockedVault#cleartextChunkSize()} bytes, may be empty
	 * @param ciphertextChunk Receives the ciphertext; needs at least {@link UnlockedVault#ciphertextChunkSize()} remaining bytes
	 * @param chunkIndex Index of the chunk
	 */
	void encryptChunk(ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkIndex);

	/**
	 * Authenticates and decrypts one chunk.
	 *
	 * @param ciphertextChunk Ciphertext from the buffer's position to its limit
	 * @param cleartextChunk Receives the cleartext; needs at least {@link UnlockedVault#cleartextChunkSize()} remaining bytes
	 * @param chunkIndex Index of the chunk
	 * @throws AuthenticationFailedException If the chunk is unauthentic or does not belong at this index
	 */
	void decryptChunk(ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException;

	// LIFECYCLE

	/**
	 * Destroys the file key.
	 */
	@Override
	void destroy();

	/**
	 * Same as {@link #destroy()}.
	 */
	@Override
	default void close() {
		destroy();
	}

}
