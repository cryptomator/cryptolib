/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import com.google.gson.annotations.Expose;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.Charset;

public class KeyFileTest {

	private static final Charset UTF_8 = Charset.forName("UTF-8");

	@Test
	public void testParse() {
		final String serialized = "{\"version\":42, \"foo\":\"AAAAAAAAAAA=\", \"hidden\": \"hello world\"}";
		KeyFile keyFile = KeyFile.parse(serialized.getBytes());
		Assertions.assertEquals(42, keyFile.getVersion());
		KeyFileImpl keyFileImpl = keyFile.as(KeyFileImpl.class);
		Assertions.assertEquals(42, keyFileImpl.getVersion());
		Assertions.assertArrayEquals(new byte[8], keyFileImpl.foo);
		Assertions.assertNull(keyFileImpl.hidden);
	}

	@Test
	public void testParseInvalid1() {
		final String serialized = "{i don't know syntax}";
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			KeyFile.parse(serialized.getBytes());
		});
	}

	@Test
	public void testParseInvalid2() {
		final byte[] serialized = new byte[10];
		Assertions.assertThrows(IllegalArgumentException.class, () -> {
			KeyFile.parse(serialized);
		});
	}

	@Test
	public void testSerialize() {
		KeyFileImpl keyFile = new KeyFileImpl();
		keyFile.foo = new byte[8];
		keyFile.hidden = "hello world";
		String serialized = new String(keyFile.serialize(), UTF_8);
		MatcherAssert.assertThat(serialized, CoreMatchers.containsString("\"foo\": \"AAAAAAAAAAA=\""));
		MatcherAssert.assertThat(serialized, CoreMatchers.not(CoreMatchers.containsString("\"hidden\": \"hello world\"")));
	}

	private static class KeyFileImpl extends KeyFile {
		@Expose
		byte[] foo;

		String hidden;
	}

}
