package org.cryptomator.cryptolib.api;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Positional read access to the ciphertext of a single file, shaped like {@link java.nio.channels.FileChannel#read(ByteBuffer, long)} so that a {@code FileChannel} can be passed as method reference.
 */
@FunctionalInterface
public interface CiphertextReader {

	/**
	 * Reads ciphertext bytes starting at the given position into the given buffer.
	 *
	 * @param dst Buffer to fill; fewer bytes than {@code dst.remaining()} may be read
	 * @param ciphertextPosition Absolute position within the ciphertext file (the header starts at 0)
	 * @return Number of bytes read, or {@code -1} if the position is at or beyond the end of the file
	 * @throws IOException If reading fails
	 */
	int read(ByteBuffer dst, long ciphertextPosition) throws IOException;

}
