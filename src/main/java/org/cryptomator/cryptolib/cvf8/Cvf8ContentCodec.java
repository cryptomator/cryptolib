package org.cryptomator.cryptolib.cvf8;

import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.internal.ChunkCodec;
import org.cryptomator.cryptolib.internal.FileHeaderParts;
import org.cryptomator.cryptolib.internal.FileLayout;

import java.nio.ByteBuffer;

/**
 * Header and chunk encryption of one CVF8 cipher combination.
 */
interface Cvf8ContentCodec extends ChunkCodec {

	FileLayout layout();

	/**
	 * @return A fresh, already encrypted header with a random nonce and content key
	 */
	FileHeaderParts createHeader();

	/**
	 * @param encryptedHeader The encrypted header, position to limit
	 * @return The decrypted header
	 * @throws AuthenticationFailedException If the header is unauthentic
	 * @throws IllegalArgumentException If the header is malformed
	 */
	FileHeaderParts decryptHeader(ByteBuffer encryptedHeader) throws AuthenticationFailedException;

}
