/*******************************************************************************
 * Copyright (c) 2016 Sebastian Stenzel and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the accompanying LICENSE.txt.
 *
 * Contributors:
 *     Sebastian Stenzel - initial API and implementation
 *******************************************************************************/
package org.cryptomator.cryptolib.api;

import java.nio.charset.StandardCharsets;

import org.hamcrest.CoreMatchers;
import org.junit.Assert;
import org.junit.Test;

import com.google.gson.annotations.Expose;

public class KeyFileTest {

	@Test
	public void testParse() {
		final String serialized = "{\"version\":42, \"foo\":\"AAAAAAAAAAA=\", \"hidden\": \"hello world\"}";
		KeyFile keyFile = KeyFile.parse(serialized.getBytes());
		Assert.assertEquals(42, keyFile.getVersion());
		KeyFileImpl keyFileImpl = keyFile.as(KeyFileImpl.class);
		Assert.assertEquals(42, keyFileImpl.getVersion());
		Assert.assertArrayEquals(new byte[8], keyFileImpl.foo);
		Assert.assertNull(keyFileImpl.hidden);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testParseInvalid1() {
		final String serialized = "{i don't know syntax}";
		KeyFile.parse(serialized.getBytes());
	}

	@Test
	public void testSerialize() {
		KeyFileImpl keyFile = new KeyFileImpl();
		keyFile.foo = new byte[8];
		keyFile.hidden = "hello world";
		String serialized = new String(keyFile.serialize(), StandardCharsets.UTF_8);
		Assert.assertThat(serialized, CoreMatchers.containsString("\"foo\": \"AAAAAAAAAAA=\""));
		Assert.assertThat(serialized, CoreMatchers.not(CoreMatchers.containsString("\"hidden\": \"hello world\"")));
	}

	private static class KeyFileImpl extends KeyFile {
		@Expose
		byte[] foo;

		String hidden;
	}

}
