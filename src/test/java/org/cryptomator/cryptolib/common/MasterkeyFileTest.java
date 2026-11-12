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

class MasterkeyFileTest {

	@Nested
	@DisplayName("isValid()")
	class IsValid {

		private MasterkeyFile masterkeyFile;

		@BeforeEach
		void setup() {
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
		void testDefaultsAreValid() {
			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@Test
		@DisplayName("scrypt parameters exceeding the memory limit are valid, as resource limits are left to MasterkeyFileValidator")
		void testOversizedScryptParamsAreValid() {
			masterkeyFile.scryptCostParam = Integer.MAX_VALUE;
			masterkeyFile.scryptBlockSize = Integer.MAX_VALUE;

			Assertions.assertTrue(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptCostParam = {0}")
		@DisplayName("out of range scryptCostParam is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0, 1})
		void testOutOfRangeCostParamIsInvalid(int scryptCostParam) {
			masterkeyFile.scryptCostParam = scryptCostParam;

			Assertions.assertFalse(masterkeyFile.isValid());
		}

		@ParameterizedTest(name = "scryptBlockSize = {0}")
		@DisplayName("out of range scryptBlockSize is invalid")
		@ValueSource(ints = {Integer.MIN_VALUE, -1, 0})
		void testOutOfRangeBlockSizeIsInvalid(int scryptBlockSize) {
			masterkeyFile.scryptBlockSize = scryptBlockSize;

			Assertions.assertFalse(masterkeyFile.isValid());
		}

	}

	@Test
	void testRead() throws IOException {
		MasterkeyFile masterkeyFile = MasterkeyFile.read(new StringReader("{\"scryptSalt\": \"Zm9v\"}"));

		Assertions.assertArrayEquals("foo".getBytes(), masterkeyFile.scryptSalt);
	}

	@Test
	void testWrite() throws IOException {
		MasterkeyFile masterkeyFile = new MasterkeyFile();
		masterkeyFile.scryptSalt = "foo".getBytes();

		StringWriter jsonWriter = new StringWriter();
		masterkeyFile.write(jsonWriter);
		String json = jsonWriter.toString();

		MatcherAssert.assertThat(json, CoreMatchers.containsString("\"scryptSalt\": \"Zm9v\""));
	}

	@Test
	@DisplayName("read() maps all members, ignores unknown ones and leaves missing or null ones unset")
	void testReadAllMembers() throws IOException {
		String json = "{\"version\": 999, \"scryptSalt\": \"AAAAAAAAAAA=\", \"scryptCostParam\": 32768, \"scryptBlockSize\": 8.0, \"primaryMasterKey\": \"Zm9v\", \"versionMac\": null, \"unknown\": [1]}";

		MasterkeyFile masterkeyFile = MasterkeyFile.read(new StringReader(json));

		Assertions.assertEquals(999, masterkeyFile.version);
		Assertions.assertArrayEquals(new byte[8], masterkeyFile.scryptSalt);
		Assertions.assertEquals(32768, masterkeyFile.scryptCostParam);
		Assertions.assertEquals(8, masterkeyFile.scryptBlockSize, "an integer written with a fraction");
		Assertions.assertArrayEquals("foo".getBytes(), masterkeyFile.encMasterKey);
		Assertions.assertNull(masterkeyFile.macMasterKey);
		Assertions.assertNull(masterkeyFile.versionMac);
	}

	@ParameterizedTest(name = "read() rejects {0}")
	@ValueSource(strings = {"", "null", "[]", "\"text\"", "{", "{\"version\": 1.5}", "{\"version\": 4294967296}", "{\"version\": \"999\"}", "{\"version\": true}", "{\"scryptSalt\": 1}", "{\"scryptSalt\": \"!\"}"})
	void testReadInvalid(String json) {
		StringReader reader = new StringReader(json);

		Assertions.assertThrows(IOException.class, () -> MasterkeyFile.read(reader));
	}

	@Test
	@DisplayName("write() emits indented JSON with unescaped base64 padding and omits unset members")
	void testWriteFormat() throws IOException {
		MasterkeyFile masterkeyFile = new MasterkeyFile();
		masterkeyFile.version = 999;
		masterkeyFile.scryptSalt = new byte[8];
		masterkeyFile.scryptCostParam = 32768;
		masterkeyFile.scryptBlockSize = 8;
		masterkeyFile.encMasterKey = "foo".getBytes();

		StringWriter jsonWriter = new StringWriter();
		masterkeyFile.write(jsonWriter);

		Assertions.assertEquals("{\n  \"version\": 999,\n  \"scryptSalt\": \"AAAAAAAAAAA=\",\n  \"scryptCostParam\": 32768,\n  \"scryptBlockSize\": 8,\n  \"primaryMasterKey\": \"Zm9v\"\n}", jsonWriter.toString());
	}

}