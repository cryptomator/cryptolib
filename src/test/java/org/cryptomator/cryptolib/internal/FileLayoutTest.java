package org.cryptomator.cryptolib.internal;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class FileLayoutTest {

	@Nested
	@DisplayName("without EOF chunk (CVF8 SIV_GCM: 68 + n * (12 + 32768 + 16))")
	class WithoutEofChunk {

		private final FileLayout layout = new FileLayout(68, 32768, 32796, false);

		@ParameterizedTest(name = "ciphertextSize({0}) == {1}")
		@CsvSource({"0,68", "1,97", "32767,32863", "32768,32864", "32769,32893", "65536,65660", "65537,65689"})
		void testCiphertextSize(long cleartextSize, long ciphertextSize) {
			Assertions.assertEquals(ciphertextSize, layout.ciphertextSize(cleartextSize));
			Assertions.assertEquals(cleartextSize, layout.cleartextSize(ciphertextSize));
		}

		@ParameterizedTest(name = "cleartextSize({0}) throws")
		@ValueSource(longs = {-1, 0, 67, 69, 68 + 28, 68 + 32796 + 1, 68 + 32796 + 28})
		void testInvalidCiphertextSize(long ciphertextSize) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> layout.cleartextSize(ciphertextSize));
		}

		@ParameterizedTest(name = "chunkCount({0}) == {1}")
		@CsvSource({"0,0", "1,1", "32768,1", "32769,2", "65536,2", "65537,3"})
		void testChunkCount(long cleartextSize, long chunkCount) {
			Assertions.assertEquals(chunkCount, layout.chunkCount(cleartextSize));
		}

		@Test
		void testChunkLengths() {
			Assertions.assertEquals(32768, layout.cleartextChunkLength(40000, 0));
			Assertions.assertEquals(40000 - 32768, layout.cleartextChunkLength(40000, 1));
			Assertions.assertEquals(-1, layout.cleartextChunkLength(40000, 2));
			Assertions.assertEquals(32796, layout.ciphertextChunkLength(40000, 0));
			Assertions.assertEquals(40000 - 32768 + 28, layout.ciphertextChunkLength(40000, 1));
			Assertions.assertEquals(-1, layout.cleartextChunkLength(0, 0));
		}

	}

	@Nested
	@DisplayName("with EOF chunk (UVF: 68 + n * (12 + 32740 + 16))")
	class WithEofChunk {

		private final FileLayout layout = new FileLayout(68, 32740, 32768, true);

		@ParameterizedTest(name = "ciphertextSize({0}) == {1}")
		@CsvSource({"0,96", "1,97", "32739,32835", "32740,32864", "32741,32865", "65480,65632", "65481,65633"})
		void testCiphertextSize(long cleartextSize, long ciphertextSize) {
			Assertions.assertEquals(ciphertextSize, layout.ciphertextSize(cleartextSize));
			Assertions.assertEquals(cleartextSize, layout.cleartextSize(ciphertextSize));
		}

		@ParameterizedTest(name = "cleartextSize({0}) throws")
		@ValueSource(longs = {68, 69, 95, 68 + 32768, 68 + 32768 + 27, 68 + 2 * 32768})
		void testInvalidCiphertextSize(long ciphertextSize) {
			Assertions.assertThrows(IllegalArgumentException.class, () -> layout.cleartextSize(ciphertextSize));
		}

		@ParameterizedTest(name = "chunkCount({0}) == {1}")
		@CsvSource({"0,1", "1,1", "32739,1", "32740,2", "32741,2", "65480,3"})
		void testChunkCount(long cleartextSize, long chunkCount) {
			Assertions.assertEquals(chunkCount, layout.chunkCount(cleartextSize));
		}

		@Test
		void testChunkLengths() {
			Assertions.assertEquals(32740, layout.cleartextChunkLength(32740, 0));
			Assertions.assertEquals(0, layout.cleartextChunkLength(32740, 1)); // EOF chunk
			Assertions.assertEquals(-1, layout.cleartextChunkLength(32740, 2));
			Assertions.assertEquals(28, layout.ciphertextChunkLength(32740, 1));
			Assertions.assertEquals(0, layout.cleartextChunkLength(0, 0));
		}

	}

	@Test
	void testOffsets() {
		FileLayout layout = new FileLayout(88, 32768, 32816, false);
		Assertions.assertEquals(0, layout.chunkIndex(0));
		Assertions.assertEquals(0, layout.chunkIndex(32767));
		Assertions.assertEquals(1, layout.chunkIndex(32768));
		Assertions.assertEquals(32767, layout.offsetInChunk(32767));
		Assertions.assertEquals(0, layout.offsetInChunk(32768));
		Assertions.assertEquals(88, layout.ciphertextChunkOffset(0));
		Assertions.assertEquals(88 + 32816, layout.ciphertextChunkOffset(1));
		Assertions.assertEquals(32768, layout.cleartextChunkOffset(1));
		Assertions.assertEquals(48, layout.chunkOverhead());
	}

}
