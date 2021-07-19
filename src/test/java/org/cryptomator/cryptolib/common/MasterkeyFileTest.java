package org.cryptomator.cryptolib.common;

import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

public class MasterkeyFileTest {

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