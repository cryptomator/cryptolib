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
		@DisplayName("scrypt parameters exceeding the memory limit are valid, as resource limits are left to MasterkeyFileValidator")
		public void testOversizedScryptParamsAreValid() {
			masterkeyFile.scryptCostParam = Integer.MAX_VALUE;
			masterkeyFile.scryptBlockSize = Integer.MAX_VALUE;

			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptCostParam = {0}")
		@DisplayName("out of range scryptCostParam is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 1})
		public void testOutOfRangeCostParamIsInvalid(int scryptCostParam) {
			masterkeyFile.scryptCostParam = scryptCostParam;

			Assertions.assertFalse(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptBlockSize = {0}")
		@DisplayName("out of range scryptBlockSize is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0})
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