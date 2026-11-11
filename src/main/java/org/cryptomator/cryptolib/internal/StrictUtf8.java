package org.cryptomator.cryptolib.internal;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * UTF-8 decoding that reports malformed input instead of replacing it.
 */
public final class StrictUtf8 {

	private StrictUtf8() {
	}

	/**
	 * @param bytes Allegedly UTF-8 encoded text
	 * @return The decoded text
	 * @throws CharacterCodingException If {@code bytes} is not valid UTF-8
	 */
	public static String decode(byte[] bytes) throws CharacterCodingException {
		return StandardCharsets.UTF_8.newDecoder() //
				.onMalformedInput(CodingErrorAction.REPORT) //
				.onUnmappableCharacter(CodingErrorAction.REPORT) //
				.decode(ByteBuffer.wrap(bytes)) //
				.toString();
	}

}
