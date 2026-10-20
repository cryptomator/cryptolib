package org.cryptomator.cryptolib.common;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.HashSet;
import java.util.Random;
import java.util.stream.IntStream;
import java.util.stream.Stream;

class WordEncoderTest {

	private static final Random PRNG = new Random(42L);
	private final WordEncoder encoder = WordEncoder.ENGLISH;

	@Test
	@DisplayName("dictionary has 4096 distinct words")
	void testDictionary() {
		Assertions.assertEquals(4096, encoder.words().size());
		Assertions.assertEquals(4096, new HashSet<>(encoder.words()).size());
		Assertions.assertEquals("ad", encoder.words().get(0));
		Assertions.assertThrows(UnsupportedOperationException.class, () -> encoder.words().add("x"));
	}

	@DisplayName("decode(encode(input)) == input")
	@ParameterizedTest(name = "{index} * 3 bytes")
	@MethodSource("createRandomByteSequences")
	void encodeAndDecode(byte[] input) {
		String encoded = encoder.encodePadded(input);
		byte[] decoded = encoder.decode(encoded);
		Assertions.assertArrayEquals(input, decoded);
	}

	static Stream<byte[]> createRandomByteSequences() {
		return IntStream.range(0, 30).mapToObj(i -> {
			byte[] randomBytes = new byte[i * 3];
			PRNG.nextBytes(randomBytes);
			return randomBytes;
		});
	}

	@Test
	@DisplayName("known encodings")
	void testKnownEncodings() {
		Assertions.assertEquals("", encoder.encodePadded(new byte[0]));
		Assertions.assertEquals("ad ad", encoder.encodePadded(new byte[3]));
		Assertions.assertEquals("water water", encoder.encodePadded(new byte[]{0x55, 0x55, 0x55})); // 0x555 0x555
		Assertions.assertEquals("water asset", encoder.encodePadded(new byte[]{0x55, 0x55, 0x77})); // 0x555 0x577
		Assertions.assertEquals("partly partly", encoder.encodePadded(new byte[]{0x77, 0x77, 0x77}));
	}

	@Test
	@DisplayName("input not a multiple of three bytes")
	void testEncodeUnpadded() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.encodePadded(new byte[1]));
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.encodePadded(new byte[4]));
	}

	@Test
	@DisplayName("decoding tolerates any whitespace")
	void testDecodeWhitespace() {
		Assertions.assertArrayEquals(new byte[6], encoder.decode("  ad\tad\n\n ad   ad \r\n"));
		Assertions.assertArrayEquals(new byte[0], encoder.decode(""));
		Assertions.assertArrayEquals(new byte[0], encoder.decode(null));
	}

	@Test
	@DisplayName("odd word count and unknown words are rejected")
	void testDecodeInvalid() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.decode("ad"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.decode("ad ad ad"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.decode("hallo bonjour"));
		Assertions.assertThrows(IllegalArgumentException.class, () -> encoder.decode("Ad ad"), "case-sensitive");
	}

	@Test
	@DisplayName("missing dictionary")
	void testMissingDictionary() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> new WordEncoder("/does/not/exist.txt"));
	}

}
