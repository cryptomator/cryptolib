package org.cryptomator.cryptolib.common;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

public class MasterkeyFileTest {

	@Nested
	@DisplayName("isValid()")
	class IsValid {

		private MasterkeyFile masterkeyFile;

		@BeforeEach
		public void setup() {
			masterkeyFile = new MasterkeyFile();
			masterkeyFile.version = 999;
			masterkeyFile.scryptSalt = new byte[8];
			masterkeyFile.scryptCostParam = 32768;
			masterkeyFile.scryptBlockSize = 8;
			masterkeyFile.encMasterKey = new byte[40];
			masterkeyFile.macMasterKey = new byte[40];
			masterkeyFile.versionMac = new byte[32];
		}

		@Test
		@DisplayName("default parameters are valid")
		public void testDefaultsAreValid() {
			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("scryptCostParam at the upper bound is valid")
		public void testMaxCostParamIsValid() {
			masterkeyFile.scryptCostParam = MasterkeyFile.MAX_SCRYPT_COST_PARAM;

			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("scryptBlockSize at the upper bound is valid")
		public void testMaxBlockSizeIsValid() {
			masterkeyFile.scryptBlockSize = MasterkeyFile.MAX_SCRYPT_BLOCK_SIZE;

			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("scryptCostParam * scryptBlockSize at the memory limit is valid")
		public void testProductAtMemoryLimitIsValid() {
			masterkeyFile.scryptCostParam = 1 << 19;
			masterkeyFile.scryptBlockSize = 16; // 2^19 * 16 * 128 = 1 GiB

			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("scryptCostParam * scryptBlockSize exceeding the memory limit is invalid")
		public void testProductExceedingMemoryLimitIsInvalid() {
			masterkeyFile.scryptCostParam = 1 << 20;
			masterkeyFile.scryptBlockSize = 16; // 2^20 * 16 * 128 = 2 GiB, while both factors are within their individual bounds

			Assertions.assertFalse(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("both scrypt parameters at their upper bounds are invalid")
		public void testBothUpperBoundsAreInvalid() {
			masterkeyFile.scryptCostParam = MasterkeyFile.MAX_SCRYPT_COST_PARAM;
			masterkeyFile.scryptBlockSize = MasterkeyFile.MAX_SCRYPT_BLOCK_SIZE; // 2^20 * 64 * 128 = 8 GiB

			Assertions.assertFalse(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptCostParam = {0}")
		@DisplayName("out of range scryptCostParam is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 1, MasterkeyFile.MAX_SCRYPT_COST_PARAM + 1, MasterkeyFile.MAX_SCRYPT_COST_PARAM << 1, Integer.MAX_VALUE})
		public void testOutOfRangeCostParamIsInvalid(int scryptCostParam) {
			masterkeyFile.scryptCostParam = scryptCostParam;

			Assertions.assertFalse(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptBlockSize = {0}")
		@DisplayName("out of range scryptBlockSize is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0, MasterkeyFile.MAX_SCRYPT_BLOCK_SIZE + 1, MasterkeyFile.MAX_SCRYPT_BLOCK_SIZE << 1, Integer.MAX_VALUE})
		public void testOutOfRangeBlockSizeIsInvalid(int scryptBlockSize) {
			masterkeyFile.scryptBlockSize = scryptBlockSize;

			Assertions.assertFalse(masterkeyFile.isValid());
		}

	}

	@Test
	public void testRead() throws IOException {
		MasterkeyFile masterkeyFile = MasterkeyFile.read(new StringReader("{\"scryptSalt\": \"Zm9v\"}"));

		Assertions.assertArrayEquals("foo".getBytes(), masterkeyFile.scryptSalt);
	}

	@Test
	public void testWrite() throws IOException {
		MasterkeyFile masterkeyFile = new MasterkeyFile();
		masterkeyFile.scryptSalt = "foo".getBytes();

		StringWriter jsonWriter = new StringWriter();
		masterkeyFile.write(jsonWriter);
		String json = jsonWriter.toString();

		MatcherAssert.assertThat(json, CoreMatchers.containsString("\"scryptSalt\": \"Zm9v\""));
	}

}