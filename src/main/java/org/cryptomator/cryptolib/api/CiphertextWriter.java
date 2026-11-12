package org.cryptomator.cryptolib.api;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Positional write access to the ciphertext of a single file, shaped like {@link java.nio.channels.FileChannel#write(ByteBuffer, long)} so that a {@code FileChannel} can be passed as method reference.
 */
@FunctionalInterface
public interface CiphertextWriter {

	/**
	 * Writes the remaining bytes of the given buffer to the ciphertext file at the given position.
	 *
	 * @param src Buffer whose remaining bytes are written; fewer bytes may be written, in which case cryptolib calls this method again
	 * @param ciphertextPosition Absolute position within the ciphertext file (the header starts at 0)
	 * @return Number of bytes written
	 * @throws IOException If writing fails
	 */
	int write(ByteBuffer src, long ciphertextPosition) throws IOException;

}
