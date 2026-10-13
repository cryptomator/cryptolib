package org.cryptomator.cryptolib.internal;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.common.DestroyableSecretKey;

import java.nio.ByteBuffer;

/**
 * Format-specific encryption of a single content chunk, bound to a file's header nonce and file key.
 */
public interface ChunkCodec {

	/**
	 * @param headerNonce The file header's nonce
	 * @param fileKey The file's content key
	 * @param cleartextChunk Cleartext from position to limit, at most one chunk
	 * @param ciphertextChunk Receives the ciphertext; must have at least {@code cleartextChunk.remaining() + overhead} remaining bytes
	 * @param chunkIndex Index of the chunk
	 */
	void encryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer cleartextChunk, ByteBuffer ciphertextChunk, long chunkIndex);

	/**
	 * @param headerNonce The file header's nonce
	 * @param fileKey The file's content key
	 * @param ciphertextChunk Ciphertext from position to limit
	 * @param cleartextChunk Receives the cleartext; must have at least one full chunk of remaining bytes
	 * @param chunkIndex Index of the chunk
	 * @throws AuthenticationFailedException If the chunk is unauthentic
	 */
	void decryptChunk(byte[] headerNonce, DestroyableSecretKey fileKey, ByteBuffer ciphertextChunk, ByteBuffer cleartextChunk, long chunkIndex) throws AuthenticationFailedException;

}
