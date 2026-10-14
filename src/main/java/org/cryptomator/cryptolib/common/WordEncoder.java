package org.cryptomator.cryptolib.common;

import com.google.common.base.CharMatcher;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;
import com.google.common.base.Strings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Encodes bytes as a sequence of words from a 4096-word dictionary (twelve bits per word, three bytes per two words), as used for human-readable recovery keys.
 */
public final class WordEncoder {

	/** The English dictionary shared by Cryptomator, Cryptomator Hub and cryptolib. */
	public static final WordEncoder ENGLISH = new WordEncoder("/org/cryptomator/cryptolib/common/4096words_en.txt");

	private static final int WORD_COUNT = 4096;
	private static final char DELIMITER = ' ';
	private static final Splitter SPLITTER = Splitter.on(CharMatcher.whitespace()).omitEmptyStrings();

	private final List<String> words;
	private final Map<String, Integer> indices;

	// visible for testing
	WordEncoder(String wordFile) {
		List<String> read = new ArrayList<>(WORD_COUNT);
		try (InputStream in = getClass().getResourceAsStream(wordFile); //
			 BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.US_ASCII.newDecoder()))) {
			String line;
			while (read.size() < WORD_COUNT && (line = reader.readLine()) != null) {
				read.add(line);
			}
		} catch (IOException | NullPointerException e) {
			throw new IllegalArgumentException("Unreadable file: " + wordFile, e);
		}
		if (read.size() < WORD_COUNT) {
			throw new IllegalArgumentException("Insufficient input file: " + wordFile);
		}
		this.words = Collections.unmodifiableList(read);
		Map<String, Integer> index = new HashMap<>(WORD_COUNT * 2);
		for (int i = 0; i < WORD_COUNT; i++) {
			index.put(read.get(i), i);
		}
		this.indices = Collections.unmodifiableMap(index);
	}

	/**
	 * @return All words of the dictionary in encoding order (unmodifiable), e.g. for input completion
	 */
	public List<String> words() {
		return words;
	}

	/**
	 * Encodes the given input as a sequence of space-separated words.
	 *
	 * @param input A multiple of three bytes
	 * @return A string that can be {@link #decode(String) decoded} to the input again
	 * @throws IllegalArgumentException If input is not a multiple of three bytes
	 */
	public String encodePadded(byte[] input) {
		Preconditions.checkArgument(input.length % 3 == 0, "input needs to be padded to a multiple of three");
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < input.length; i += 3) {
			byte b1 = input[i];
			byte b2 = input[i + 1];
			byte b3 = input[i + 2];
			int firstWordIndex = (0xFF0 & (b1 << 4)) + (0x00F & (b2 >> 4)); // 0xFFF000
			int secondWordIndex = (0xF00 & (b2 << 8)) + (0x0FF & b3); // 0x000FFF
			assert firstWordIndex < WORD_COUNT;
			assert secondWordIndex < WORD_COUNT;
			sb.append(words.get(firstWordIndex)).append(DELIMITER);
			sb.append(words.get(secondWordIndex)).append(DELIMITER);
		}
		if (sb.length() > 0) {
			sb.setLength(sb.length() - 1); // remove last space
		}
		return sb.toString();
	}

	/**
	 * Decodes a sequence of words separated by any whitespace that has previously been {@link #encodePadded(byte[]) encoded}.
	 *
	 * @param encoded The word sequence
	 * @return Decoded bytes
	 * @throws IllegalArgumentException If the encoded string doesn't consist of a multiple of two words or one of the words is unknown to this encoder
	 */
	public byte[] decode(String encoded) {
		List<String> split = SPLITTER.splitToList(Strings.nullToEmpty(encoded));
		Preconditions.checkArgument(split.size() % 2 == 0, "input needs to be a multiple of two words");
		byte[] result = new byte[split.size() / 2 * 3];
		for (int i = 0; i < split.size(); i += 2) {
			String w1 = split.get(i);
			String w2 = split.get(i + 1);
			int firstWordIndex = indices.getOrDefault(w1, -1);
			int secondWordIndex = indices.getOrDefault(w2, -1);
			Preconditions.checkArgument(firstWordIndex != -1, "%s not in dictionary", w1);
			Preconditions.checkArgument(secondWordIndex != -1, "%s not in dictionary", w2);
			byte b1 = (byte) (0xFF & (firstWordIndex >> 4));
			byte b2 = (byte) ((0xF0 & (firstWordIndex << 4)) + (0x0F & (secondWordIndex >> 8)));
			byte b3 = (byte) (0xFF & secondWordIndex);
			result[i / 2 * 3] = b1;
			result[i / 2 * 3 + 1] = b2;
			result[i / 2 * 3 + 2] = b3;
		}
		return result;
	}

}
